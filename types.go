package sdk

import "encoding/json"

// Network represents an Aleo network variant.
type Network string

const (
	// MainnetV0 is the Aleo mainnet.
	MainnetV0 Network = "mainnet"
	// TestnetV0 is the Aleo testnet.
	TestnetV0 Network = "testnet"
	// CanaryV0 is the Aleo canary network.
	CanaryV0 Network = "canary"
)

// String returns the network name.
func (n Network) String() string { return string(n) }

// Valid reports whether n is a known network.
func (n Network) Valid() bool {
	switch n {
	case MainnetV0, TestnetV0, CanaryV0:
		return true
	default:
		return false
	}
}

// Authorization is the JSON-serializable authorization produced by snarkVM's
// Process::authorize.
type Authorization struct {
	Raw json.RawMessage
}

// String returns the raw authorization JSON.
func (a *Authorization) String() string {
	return string(a.Raw)
}

// MarshalJSON implements json.Marshaler.
func (a *Authorization) MarshalJSON() ([]byte, error) {
	return a.Raw, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *Authorization) UnmarshalJSON(data []byte) error {
	a.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// Block represents an Aleo block returned by the REST API.
type Block struct {
	Hash                  string          `json:"block_hash"`
	PreviousHash          string          `json:"previous_hash"`
	Height                uint64          `json:"height"`
	Header                json.RawMessage `json:"header"`
	Authority             json.RawMessage `json:"authority,omitempty"`
	Ratifications         json.RawMessage `json:"ratifications,omitempty"`
	Solutions             json.RawMessage `json:"solutions,omitempty"`
	AbortedSolutionIDs    json.RawMessage `json:"aborted_solution_ids,omitempty"`
	Transactions          json.RawMessage `json:"transactions,omitempty"`
	AbortedTransactionIDs json.RawMessage `json:"aborted_transaction_ids,omitempty"`
}

// Transaction represents an Aleo transaction from the REST API.
type Transaction struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Execution  json.RawMessage `json:"execution,omitempty"`
	Fee        json.RawMessage `json:"fee,omitempty"`
	Deployment json.RawMessage `json:"deployment,omitempty"`
}

// ExecutionResult holds the result of an offline program execution.
type ExecutionResult struct {
	Raw json.RawMessage
}

// ProvingRequest is the payload sent to the Provable /prove endpoint.
type ProvingRequest struct {
	Authorization    json.RawMessage `json:"authorization"`
	FeeAuthorization json.RawMessage `json:"fee_authorization"`
	Broadcast        bool            `json:"broadcast"`
}

// ProvingResponse is the response from the Provable /prove endpoint.
type ProvingResponse struct {
	Transaction     json.RawMessage  `json:"transaction"`
	BroadcastResult *BroadcastResult `json:"broadcast_result,omitempty"`
}

// BroadcastResult contains the result of a transaction broadcast by the prover.
type BroadcastResult struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

// TransactionID extracts the transaction ID from a ProvingResponse.
func (r *ProvingResponse) TransactionID() (string, error) {
	if len(r.Transaction) == 0 {
		return "", ErrEmptyTransaction
	}
	var tx struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(r.Transaction, &tx); err != nil {
		return "", err
	}
	if tx.ID == "" {
		return "", ErrEmptyTransactionID
	}
	return tx.ID, nil
}

// DelegatedProvingParams configures a proving request submission.
// This is the Go equivalent of the JS SDK's DelegatedProvingParams.
type DelegatedProvingParams struct {
	// ProvingRequest is the request to submit.
	ProvingRequest *ProvingRequest

	// DPSPrivacy enables the encrypted proving flow (GET /pubkey + POST /prove/encrypted).
	// When false, the unencrypted POST /prove endpoint is used.
	DPSPrivacy bool

	// URL overrides the prover base URL for this request.
	// If empty, the ProvableClient's configured prover URL is used.
	URL string
}

// ProvingResult is the discriminated result of SubmitProvingRequestSafe.
// Check OK to determine whether Data or Error is populated.
type ProvingResult struct {
	// OK is true when the proving request succeeded.
	OK bool

	// Data holds the proving response when OK is true.
	Data *ProvingResponse

	// Status is the HTTP status code when OK is false.
	Status int

	// Error holds the error details when OK is false.
	Error *ProvingError
}

// ProvingError holds the error message from a failed proving request.
type ProvingError struct {
	Message string `json:"message"`
}

// PubKeyResponse is the response from GET /pubkey on the DPS.
type PubKeyResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// EncryptedProvingRequest is the payload sent to POST /prove/encrypted.
type EncryptedProvingRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"`
}
