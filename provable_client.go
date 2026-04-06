package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/debendraoli/provable-sdk/internal/ffi"
)

// ProvableConfig holds configuration for the Provable delegated proving service.
type ProvableConfig struct {
	// APIKey is the Provable API key (not the env var name, the actual key).
	APIKey string

	// ConsumerID is the Provable consumer ID.
	ConsumerID string

	// ProverURL overrides the default prover endpoint.
	// Defaults to "https://api.provable.com/prove/{network}".
	ProverURL string

	// Network is "testnet" or "mainnet". Used to derive URLs if ProverURL is empty.
	Network string

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client
}

// ProvableClient communicates with the Provable delegated proving service.
// It handles JWT lifecycle, encrypted/unencrypted proving flows, and retry logic.
//
// This is the Go equivalent of the DPS-related methods on AleoNetworkClient in the JS SDK.
type ProvableClient struct {
	apiKey     string
	consumerID string
	apiBase    string // base URL for JWT endpoint (e.g. "https://api.provable.com")
	proverBase string
	http       *http.Client

	// Retry configuration for proving requests.
	maxRetries int
	baseDelay  time.Duration

	// JWT cache.
	jwtMu  sync.Mutex
	jwt    string
	jwtExp time.Time
}

// NewProvableClient creates a new Provable DPS client.
func NewProvableClient(cfg ProvableConfig) (*ProvableClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("provable API key is required")
	}
	if cfg.ConsumerID == "" {
		return nil, fmt.Errorf("provable consumer ID is required")
	}

	proverBase := cfg.ProverURL
	if proverBase == "" {
		network := cfg.Network
		if network == "" {
			network = "testnet"
		}
		proverBase = fmt.Sprintf("https://api.provable.com/prove/%s", network)
	}
	proverBase = strings.TrimRight(proverBase, "/")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}

	// Derive apiBase: if proverBase looks like https://api.provable.com/prove/...,
	// extract the origin. Otherwise use proverBase itself (e.g. test servers).
	apiBase := proverBase
	if idx := strings.Index(proverBase, "/prove"); idx > 0 {
		apiBase = proverBase[:idx]
	}

	return &ProvableClient{
		apiKey:     cfg.APIKey,
		consumerID: cfg.ConsumerID,
		apiBase:    apiBase,
		proverBase: proverBase,
		http:       httpClient,
		maxRetries: 3,
		baseDelay:  1 * time.Second,
	}, nil
}

// SetProverURI sets the prover base URL. Provide the full network-specific URL
// (e.g. "https://api.provable.com/prove/mainnet").
func (c *ProvableClient) SetProverURI(base string) {
	c.proverBase = strings.TrimRight(base, "/")
}

// jwtBufferDuration is how long before expiration we refresh the JWT.
const jwtBufferDuration = 5 * time.Minute

// GetJWT obtains a JWT token from the Provable API. The JWT is cached and
// automatically refreshed before expiration.
func (c *ProvableClient) GetJWT(ctx context.Context) (string, error) {
	c.jwtMu.Lock()
	defer c.jwtMu.Unlock()

	if c.jwt != "" && time.Now().Before(c.jwtExp.Add(-jwtBufferDuration)) {
		return c.jwt, nil
	}

	jwt, err := c.fetchJWT(ctx)
	if err != nil {
		return "", err
	}

	c.jwt = jwt
	c.jwtExp = parseJWTExpiry(jwt)
	return jwt, nil
}

// parseJWTExpiry extracts the "exp" claim from a JWT token.
// Falls back to 1 hour from now if parsing fails.
func parseJWTExpiry(token string) time.Time {
	fallback := time.Now().Add(1 * time.Hour)

	// Strip "Bearer " prefix if present.
	raw := strings.TrimPrefix(token, "Bearer ")

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return fallback
	}

	// Decode the payload (second part), handling unpadded base64url.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}

	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fallback
	}

	expUnix, err := claims.Exp.Int64()
	if err != nil || expUnix <= 0 {
		return fallback
	}

	return time.Unix(expUnix, 0)
}

func (c *ProvableClient) fetchJWT(ctx context.Context) (string, error) {
	jwtURL := fmt.Sprintf("%s/jwts/%s", c.apiBase, c.consumerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, jwtURL, nil)
	if err != nil {
		return "", fmt.Errorf("create JWT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Provable-API-Key", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("JWT request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("JWT request failed (status %d): %s", resp.StatusCode, string(body))
	}

	jwt := resp.Header.Get("Authorization")
	if jwt == "" {
		return "", fmt.Errorf("JWT response missing Authorization header")
	}
	return jwt, nil
}

// GetPublicKey fetches an ephemeral X25519 public key from the DPS for encrypted proving.
func (c *ProvableClient) GetPublicKey(ctx context.Context, jwt string) (*PubKeyResponse, error) {
	return c.getPublicKey(ctx, jwt, c.proverBase)
}

func (c *ProvableClient) getPublicKey(ctx context.Context, jwt, proverBase string) (*PubKeyResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proverBase+"/pubkey", nil)
	if err != nil {
		return nil, fmt.Errorf("create pubkey request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", jwt)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pubkey request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pubkey response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pubkey request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var pubkey PubKeyResponse
	if err := json.Unmarshal(body, &pubkey); err != nil {
		return nil, fmt.Errorf("decode pubkey response: %w", err)
	}
	return &pubkey, nil
}

// SubmitProvingRequest submits a proving request to the DPS and returns the response.
// On HTTP 400/500/503, an error is returned (with retry on 500/503).
//
// This is the Go equivalent of the JS SDK's AleoNetworkClient.submitProvingRequest().
func (c *ProvableClient) SubmitProvingRequest(ctx context.Context, params DelegatedProvingParams) (*ProvingResponse, error) {
	result, err := c.SubmitProvingRequestSafe(ctx, params)
	if err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("%w (status %d): %s", ErrProvingFailed, result.Status, result.Error.Message)
	}
	return result.Data, nil
}

// SubmitProvingRequestSafe submits a proving request without returning an error for HTTP
// failures. Instead, it returns a ProvingResult with OK=false and the error details.
// Only transport/encoding errors return a Go error.
//
// This is the Go equivalent of the JS SDK's AleoNetworkClient.submitProvingRequestSafe().
func (c *ProvableClient) SubmitProvingRequestSafe(ctx context.Context, params DelegatedProvingParams) (*ProvingResult, error) {
	proverBase := c.proverBase
	if params.URL != "" {
		proverBase = strings.TrimRight(params.URL, "/")
	}

	jwt, err := c.GetJWT(ctx)
	if err != nil {
		return nil, fmt.Errorf("get JWT: %w", err)
	}

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.baseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		var result *ProvingResult
		if params.DPSPrivacy {
			result, err = c.submitEncrypted(ctx, jwt, proverBase, params.ProvingRequest)
		} else {
			result, err = c.submitUnencrypted(ctx, jwt, proverBase, params.ProvingRequest)
		}
		if err != nil {
			return nil, err
		}

		if !result.OK && (result.Status == 500 || result.Status == 503) {
			continue
		}

		return result, nil
	}

	return &ProvingResult{
		OK:     false,
		Status: 503,
		Error:  &ProvingError{Message: "max retries exceeded"},
	}, nil
}

func (c *ProvableClient) submitUnencrypted(ctx context.Context, jwt, proverBase string, pr *ProvingRequest) (*ProvingResult, error) {
	reqJSON, err := json.Marshal(pr)
	if err != nil {
		return nil, fmt.Errorf("marshal proving request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proverBase+"/prove", strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("create prove request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", jwt)
	req.Header.Set("X-ALEO-METHOD", "submitProvingRequest")

	return c.doProveRequest(req)
}

func (c *ProvableClient) submitEncrypted(ctx context.Context, jwt, proverBase string, pr *ProvingRequest) (*ProvingResult, error) {
	pubkey, err := c.getPublicKey(ctx, jwt, proverBase)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	feeAuthJSON := ""
	if len(pr.FeeAuthorization) > 0 {
		feeAuthJSON = string(pr.FeeAuthorization)
	}
	bytesB64, err := ffi.ProvingRequestToBytes(string(pr.Authorization), feeAuthJSON, pr.Broadcast)
	if err != nil {
		return nil, fmt.Errorf("serialize proving request: %w", err)
	}
	prBytes, err := base64.StdEncoding.DecodeString(bytesB64)
	if err != nil {
		return nil, fmt.Errorf("decode proving request base64: %w", err)
	}

	ciphertext, err := encryptProvingRequest(pubkey.PublicKey, prBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt proving request: %w", err)
	}

	encReq := EncryptedProvingRequest{
		KeyID:      pubkey.KeyID,
		Ciphertext: ciphertext,
	}
	body, err := json.Marshal(encReq)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proverBase+"/prove/encrypted", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create encrypted prove request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", jwt)

	return c.doProveRequest(req)
}

func (c *ProvableClient) doProveRequest(req *http.Request) (*ProvingResult, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prove request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read prove response: %w", err)
	}

	return handleProvingResponse(resp.StatusCode, respBody), nil
}

func handleProvingResponse(status int, body []byte) *ProvingResult {
	if status == http.StatusOK || status == http.StatusCreated {
		var pr ProvingResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return &ProvingResult{
				OK:     false,
				Status: status,
				Error:  &ProvingError{Message: "invalid proving response format"},
			}
		}
		return &ProvingResult{OK: true, Data: &pr}
	}

	msg := extractErrMsg(body, status)
	return &ProvingResult{
		OK:     false,
		Status: status,
		Error:  &ProvingError{Message: msg},
	}
}

// Prove submits a proving request to the Provable /prove endpoint (unencrypted).
func (c *ProvableClient) Prove(ctx context.Context, provingRequest *ProvingRequest) (*ProvingResponse, error) {
	return c.SubmitProvingRequest(ctx, DelegatedProvingParams{
		ProvingRequest: provingRequest,
	})
}

// ProveWithJWT submits a proving request with a pre-obtained JWT (unencrypted).
func (c *ProvableClient) ProveWithJWT(ctx context.Context, jwt string, provingRequest *ProvingRequest) (*ProvingResponse, error) {
	result, err := c.submitUnencrypted(ctx, jwt, c.proverBase, provingRequest)
	if err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("%w (status %d): %s", ErrProvingFailed, result.Status, result.Error.Message)
	}
	return result.Data, nil
}

func extractErrMsg(body []byte, statusCode int) string {
	var errResp struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
		return errResp.Message
	}
	if len(body) > 0 {
		return string(body)
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}
