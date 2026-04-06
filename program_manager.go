package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ProgramManagerOptions configures the ProgramManager.
type ProgramManagerOptions struct {
	// Host is the Aleo node API base URL (e.g. "https://api.explorer.provable.com/v2").
	Host string

	// Network is the Aleo network.
	Network Network

	// PrivateKey is the Aleo private key string for signing authorizations.
	PrivateKey string

	// Provable configures the Provable DPS client. If nil, DPS methods will fail.
	Provable *ProvableConfig

	// HTTPClient is an optional custom HTTP client for network requests.
	HTTPClient *http.Client
}

// ProgramManager is the main SDK entry point, analogous to ProgramManager in the JS SDK.
// It combines account management, network queries, authorization building, and
// delegated proving into a single high-level interface.
type ProgramManager struct {
	account        *Account
	networkClient  *NetworkClient
	provableClient *ProvableClient
	network        Network
}

// NewProgramManager creates a new ProgramManager.
func NewProgramManager(opts ProgramManagerOptions) (*ProgramManager, error) {
	if opts.Host == "" {
		opts.Host = "https://api.explorer.provable.com/v2"
	}
	if opts.Network == "" {
		opts.Network = TestnetV0
	}

	var ncOpts []NetworkClientOption
	if opts.HTTPClient != nil {
		ncOpts = append(ncOpts, WithHTTPClient(opts.HTTPClient))
	}
	nc := NewNetworkClient(opts.Host, opts.Network, ncOpts...)

	var account *Account
	if opts.PrivateKey != "" {
		var err error
		account, err = AccountFromPrivateKey(opts.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("init account: %w", err)
		}
	}

	var provable *ProvableClient
	if opts.Provable != nil {
		if opts.Provable.Network == "" {
			opts.Provable.Network = string(opts.Network)
		}
		var err error
		provable, err = NewProvableClient(*opts.Provable)
		if err != nil {
			return nil, fmt.Errorf("init provable client: %w", err)
		}
	}

	return &ProgramManager{
		account:        account,
		networkClient:  nc,
		provableClient: provable,
		network:        opts.Network,
	}, nil
}

// Account returns the current account, or nil if not set.
func (pm *ProgramManager) Account() *Account { return pm.account }

// SetAccount sets the account for transaction signing.
func (pm *ProgramManager) SetAccount(a *Account) { pm.account = a }

// NetworkClient returns the underlying network client.
func (pm *ProgramManager) NetworkClient() *NetworkClient { return pm.networkClient }

// ProvableClient returns the underlying Provable DPS client, or nil.
func (pm *ProgramManager) ProvableClient() *ProvableClient { return pm.provableClient }

// ProvingRequestOptions configures a program execution via delegated proving.
type ProvingRequestOptions struct {
	// ProgramName is the on-chain program identifier (e.g. "my_program.aleo").
	ProgramName string

	// FunctionName is the function within the program to execute.
	FunctionName string

	// Inputs are the Aleo-typed input strings (e.g. ["1u32", "2u32"]).
	Inputs []string

	// Broadcast determines whether the prover should broadcast the final transaction.
	Broadcast bool

	// DPSPrivacy enables the encrypted proving flow (TEE).
	// When true, the proving request is encrypted with a NaCl sealed box
	// before submission to the DPS.
	DPSPrivacy bool

	// PrivateKey overrides the account key for this operation.
	PrivateKey string

	// ProverURL overrides the default prover endpoint for this request.
	ProverURL string
}

// BuildAuthorization generates a snarkVM Authorization for a program function call.
// This is the Go equivalent of the JS SDK's ProgramManager.buildAuthorization().
func (pm *ProgramManager) BuildAuthorization(ctx context.Context, opts ProvingRequestOptions) (*Authorization, error) {
	privateKey := opts.PrivateKey
	if privateKey == "" && pm.account != nil {
		privateKey = pm.account.PrivateKey()
	}
	if privateKey == "" {
		return nil, ErrNoPrivateKey
	}

	return BuildAuthorization(ctx, pm.networkClient, AuthorizationOptions{
		ProgramName:  opts.ProgramName,
		FunctionName: opts.FunctionName,
		Inputs:       opts.Inputs,
		PrivateKey:   privateKey,
	})
}

// BuildProvingRequest generates an authorization and wraps it into a ProvingRequest
// suitable for submission to the Provable /prove endpoint.
func (pm *ProgramManager) BuildProvingRequest(ctx context.Context, opts ProvingRequestOptions) (*ProvingRequest, error) {
	auth, err := pm.BuildAuthorization(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("build authorization: %w", err)
	}

	return &ProvingRequest{
		Authorization:    auth.Raw,
		FeeAuthorization: nil, // fee master: prover pays the fee
		Broadcast:        opts.Broadcast,
	}, nil
}

// BuildProvingRequestFromAuthorization wraps a pre-built authorization into a ProvingRequest.
func BuildProvingRequestFromAuthorization(auth *Authorization, broadcast bool) *ProvingRequest {
	return &ProvingRequest{
		Authorization:    auth.Raw,
		FeeAuthorization: nil,
		Broadcast:        broadcast,
	}
}

// SubmitProvingRequest builds an authorization and submits it to the DPS.
// Returns the full ProvingResponse. For most use cases, prefer ExecuteViaDPS.
func (pm *ProgramManager) SubmitProvingRequest(ctx context.Context, opts ProvingRequestOptions) (*ProvingResponse, error) {
	if pm.provableClient == nil {
		return nil, ErrProvableClientNotConfigured
	}

	provingReq, err := pm.BuildProvingRequest(ctx, opts)
	if err != nil {
		return nil, err
	}

	return pm.provableClient.SubmitProvingRequest(ctx, DelegatedProvingParams{
		ProvingRequest: provingReq,
		DPSPrivacy:     opts.DPSPrivacy,
		URL:            opts.ProverURL,
	})
}

// SubmitProvingRequestSafe is like SubmitProvingRequest but does not return an
// error for HTTP failures. Instead, check ProvingResult.OK.
func (pm *ProgramManager) SubmitProvingRequestSafe(ctx context.Context, opts ProvingRequestOptions) (*ProvingResult, error) {
	if pm.provableClient == nil {
		return nil, ErrProvableClientNotConfigured
	}

	provingReq, err := pm.BuildProvingRequest(ctx, opts)
	if err != nil {
		return nil, err
	}

	return pm.provableClient.SubmitProvingRequestSafe(ctx, DelegatedProvingParams{
		ProvingRequest: provingReq,
		DPSPrivacy:     opts.DPSPrivacy,
		URL:            opts.ProverURL,
	})
}

// ExecuteViaDPS builds an authorization and submits it to the Provable DPS for
// proof generation and optionally broadcast. Returns the transaction ID.
//
// This is the primary method for executing programs via delegated proving,
// equivalent to the JS SDK's ProgramManager.provingRequest() + submit flow.
func (pm *ProgramManager) ExecuteViaDPS(ctx context.Context, opts ProvingRequestOptions) (string, error) {
	if pm.provableClient == nil {
		return "", ErrProvableClientNotConfigured
	}

	provingReq, err := pm.BuildProvingRequest(ctx, opts)
	if err != nil {
		return "", err
	}

	result, err := pm.provableClient.SubmitProvingRequest(ctx, DelegatedProvingParams{
		ProvingRequest: provingReq,
		DPSPrivacy:     opts.DPSPrivacy,
		URL:            opts.ProverURL,
	})
	if err != nil {
		return "", fmt.Errorf("prove: %w", err)
	}

	if opts.Broadcast && result.BroadcastResult != nil {
		if result.BroadcastResult.StatusCode != http.StatusOK {
			return "", fmt.Errorf("broadcast failed: %s (status %d)",
				result.BroadcastResult.Message, result.BroadcastResult.StatusCode)
		}
	}

	return result.TransactionID()
}

// Broadcast submits a completed transaction to the Aleo network directly.
func (pm *ProgramManager) Broadcast(ctx context.Context, transaction json.RawMessage) (string, error) {
	return pm.networkClient.SubmitTransaction(ctx, transaction)
}

// GetProgram fetches the source code of a deployed program.
func (pm *ProgramManager) GetProgram(ctx context.Context, programID string) (string, error) {
	return pm.networkClient.GetProgram(ctx, programID)
}

// GetProgramImports fetches all transitive imports for a program.
func (pm *ProgramManager) GetProgramImports(ctx context.Context, programSource string) (map[string]string, error) {
	return pm.networkClient.GetProgramImports(ctx, programSource)
}

// GetMappingValue queries a mapping value from a deployed program.
func (pm *ProgramManager) GetMappingValue(ctx context.Context, programID, mappingName, key string) (string, error) {
	return pm.networkClient.GetMappingValue(ctx, programID, mappingName, key)
}
