package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
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

	// KeyCache is an optional cache for proving/verifying keys.
	KeyCache KeyCache
}

// KeyCache caches proving and verifying keys.
type KeyCache interface {
	Get(key string) ([]byte, bool)
	Set(key string, data []byte)
}

// ProgramManager is the main SDK entry point, analogous to ProgramManager in the JS SDK.
// It combines account management, network queries, authorization building, and
// delegated proving into a single high-level interface.
type ProgramManager struct {
	account        *Account
	networkClient  *NetworkClient
	provableClient *ProvableClient
	network        Network
	programCache   sync.Map // caches program source by ID
	keyCache       KeyCache
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
		keyCache:       opts.KeyCache,
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

// ─── Functional Options for Execute ──────────────────────────────────────────

// ExecuteOption configures an Execute call.
type ExecuteOption func(*ProvingRequestOptions)

// WithInputs sets the inputs for the execution.
func WithInputs(inputs ...string) ExecuteOption {
	return func(o *ProvingRequestOptions) { o.Inputs = inputs }
}

// Deprecated: WithFee is a no-op. The Provable DPS handles fee estimation
// and payment automatically. This option will be removed in a future version.
func WithFee(_ uint64) ExecuteOption {
	return func(*ProvingRequestOptions) {}
}

// WithPrivateKey overrides the account's private key.
func WithPrivateKey(pk string) ExecuteOption {
	return func(o *ProvingRequestOptions) { o.PrivateKey = pk }
}

// WithBroadcast sets whether to broadcast after proving.
func WithBroadcast(broadcast bool) ExecuteOption {
	return func(o *ProvingRequestOptions) { o.Broadcast = broadcast }
}

// WithDPSPrivacy enables encrypted proving.
func WithDPSPrivacy(privacy bool) ExecuteOption {
	return func(o *ProvingRequestOptions) { o.DPSPrivacy = privacy }
}

// WithProverURL overrides the prover endpoint.
func WithProverURL(url string) ExecuteOption {
	return func(o *ProvingRequestOptions) { o.ProverURL = url }
}

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

	// Deprecated: Fee is ignored. The Provable DPS handles fee estimation
	// and payment automatically.
	Fee uint64

	// DPSPrivacy enables the encrypted proving flow (TEE).
	// When true, the proving request is encrypted with a NaCl sealed box
	// before submission to the DPS.
	DPSPrivacy bool

	// PrivateKey overrides the account key for this operation.
	PrivateKey string

	// ProverURL overrides the default prover endpoint for this request.
	ProverURL string
}

// Execute builds an authorization and submits it to the Provable DPS for
// proof generation, using functional options.
func (pm *ProgramManager) Execute(ctx context.Context, programID, functionName string, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  programID,
		FunctionName: functionName,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// ExecuteAndWait executes via DPS and polls until the transaction is confirmed.
func (pm *ProgramManager) ExecuteAndWait(ctx context.Context, programID, functionName string, pollInterval time.Duration, opts ...ExecuteOption) (*Transaction, error) {
	o := ProvingRequestOptions{
		ProgramName:  programID,
		FunctionName: functionName,
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	txID, err := pm.ExecuteViaDPS(ctx, o)
	if err != nil {
		return nil, err
	}
	return pm.networkClient.WaitForTransaction(ctx, txID, pollInterval)
}

// ─── Credit Transfer Helpers ─────────────────────────────────────────────────

// TransferPublic transfers credits using the public (on-chain balance) flow.
func (pm *ProgramManager) TransferPublic(ctx context.Context, recipient string, amount uint64, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "transfer_public",
		Inputs:       []string{recipient, fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// TransferPrivate transfers credits using a private record.
func (pm *ProgramManager) TransferPrivate(ctx context.Context, recipient string, amount uint64, recordInput string, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "transfer_private",
		Inputs:       []string{recordInput, recipient, fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// TransferPublicToPrivate transfers credits from public balance to a private record.
func (pm *ProgramManager) TransferPublicToPrivate(ctx context.Context, recipient string, amount uint64, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "transfer_public_to_private",
		Inputs:       []string{recipient, fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// TransferPrivateToPublic transfers credits from a private record to public balance.
func (pm *ProgramManager) TransferPrivateToPublic(ctx context.Context, recipient string, amount uint64, recordInput string, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "transfer_private_to_public",
		Inputs:       []string{recordInput, recipient, fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// ─── Record Operations ──────────────────────────────────────────────────────

// Join combines two credit records into one.
func (pm *ProgramManager) Join(ctx context.Context, record1, record2 string, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "join",
		Inputs:       []string{record1, record2},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// Split divides a credit record into two records.
func (pm *ProgramManager) Split(ctx context.Context, record string, amount uint64, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "split",
		Inputs:       []string{record, fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// ─── Staking / Validator Operations ──────────────────────────────────────────

// BondValidator bonds credits to a validator.
func (pm *ProgramManager) BondValidator(ctx context.Context, validator string, withdrawAddress string, amount uint64, commissionPercent uint8, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "bond_validator",
		Inputs:       []string{validator, withdrawAddress, fmt.Sprintf("%du64", amount), fmt.Sprintf("%du8", commissionPercent)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// UnbondValidator unbonds credits from a validator.
func (pm *ProgramManager) UnbondValidator(ctx context.Context, amount uint64, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "unbond_validator",
		Inputs:       []string{fmt.Sprintf("%du64", amount)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// ClaimUnbonded claims credits that have finished the unbonding period.
func (pm *ProgramManager) ClaimUnbonded(ctx context.Context, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "claim_unbond_public",
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// SetValidatorState sets the validator's state (open/closed for delegations).
func (pm *ProgramManager) SetValidatorState(ctx context.Context, isOpen bool, opts ...ExecuteOption) (string, error) {
	o := ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "set_validator_state",
		Inputs:       []string{fmt.Sprintf("%t", isOpen)},
		Broadcast:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return pm.ExecuteViaDPS(ctx, o)
}

// ─── Batch Execution ─────────────────────────────────────────────────────────

// ExecuteRequest is a single request for batch parallel execution.
type ExecuteRequest struct {
	ProgramName  string
	FunctionName string
	Options      []ExecuteOption
}

// ExecuteResult holds the result of a single batch execution.
type ExecuteResult struct {
	TxID  string
	Error error
}

// maxBatchConcurrency is the default maximum number of concurrent DPS requests in ExecuteBatch.
const maxBatchConcurrency = 8

// ExecuteBatch executes multiple programs in parallel via DPS with bounded concurrency.
func (pm *ProgramManager) ExecuteBatch(ctx context.Context, requests []ExecuteRequest) []ExecuteResult {
	results := make([]ExecuteResult, len(requests))
	sem := make(chan struct{}, maxBatchConcurrency)
	var wg sync.WaitGroup
	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r ExecuteRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			txID, err := pm.Execute(ctx, r.ProgramName, r.FunctionName, r.Options...)
			results[idx] = ExecuteResult{TxID: txID, Error: err}
		}(i, req)
	}
	wg.Wait()
	return results
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

	auth, err := BuildAuthorizationWithCache(ctx, pm.networkClient, &pm.programCache, AuthorizationOptions{
		ProgramName:  opts.ProgramName,
		FunctionName: opts.FunctionName,
		Inputs:       opts.Inputs,
		PrivateKey:   privateKey,
	})
	if err != nil {
		return nil, err
	}
	return auth, nil
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
