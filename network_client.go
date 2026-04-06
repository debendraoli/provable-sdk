package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// NetworkClient communicates with an Aleo node's REST API (v2).
// All methods are safe for concurrent use.
type NetworkClient struct {
	host    string
	network Network
	http    *http.Client
	headers map[string]string

	// Retry configuration
	maxRetries int
	baseDelay  time.Duration
}

// NetworkClientOption configures a NetworkClient.
type NetworkClientOption func(*NetworkClient)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) NetworkClientOption {
	return func(nc *NetworkClient) { nc.http = c }
}

// WithHeader sets a custom header on all requests.
func WithHeader(key, value string) NetworkClientOption {
	return func(nc *NetworkClient) { nc.headers[key] = value }
}

// WithRetry configures retry behavior for transient errors and rate limits.
// Default: 3 retries with 500ms base delay (exponential backoff).
func WithRetry(maxRetries int, baseDelay time.Duration) NetworkClientOption {
	return func(nc *NetworkClient) {
		nc.maxRetries = maxRetries
		nc.baseDelay = baseDelay
	}
}

// NewNetworkClient creates a client for the Aleo node REST API.
//
//	host: e.g. "https://api.explorer.provable.com/v2"
//	network: e.g. TestnetV0, MainnetV0
func NewNetworkClient(host string, network Network, opts ...NetworkClientOption) *NetworkClient {
	nc := &NetworkClient{
		host:       strings.TrimRight(host, "/"),
		network:    network,
		http:       &http.Client{Timeout: 30 * time.Second},
		headers:    make(map[string]string),
		maxRetries: 3,
		baseDelay:  500 * time.Millisecond,
	}
	for _, o := range opts {
		o(nc)
	}
	return nc
}

// Host returns the configured host URL.
func (c *NetworkClient) Host() string { return c.host }

// Network returns the configured network.
func (c *NetworkClient) Network() Network { return c.network }

// basePath returns the API base path: /{network}
func (c *NetworkClient) basePath() string {
	return fmt.Sprintf("/%s", c.network)
}

// GetBlock fetches a block by height.
func (c *NetworkClient) GetBlock(ctx context.Context, height uint64) (*Block, error) {
	url := fmt.Sprintf("%s%s/block/%d", c.host, c.basePath(), height)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get block %d: %w", height, err)
	}
	var block Block
	if err := json.Unmarshal(body, &block); err != nil {
		return nil, fmt.Errorf("decode block %d: %w", height, err)
	}
	return &block, nil
}

// GetBlockByHash fetches a block by its hash.
func (c *NetworkClient) GetBlockByHash(ctx context.Context, hash string) (*Block, error) {
	url := fmt.Sprintf("%s%s/block/%s", c.host, c.basePath(), hash)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get block %s: %w", hash, err)
	}
	var block Block
	if err := json.Unmarshal(body, &block); err != nil {
		return nil, fmt.Errorf("decode block %s: %w", hash, err)
	}
	return &block, nil
}

// GetProgram fetches the source code of a deployed program.
func (c *NetworkClient) GetProgram(ctx context.Context, programID string) (string, error) {
	url := fmt.Sprintf("%s%s/program/%s", c.host, c.basePath(), programID)
	body, err := c.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("get program %s: %w", programID, err)
	}
	return string(body), nil
}

// GetProgramImports fetches the imports of a program as a map of programID -> source.
// This recursively resolves all transitive imports.
func (c *NetworkClient) GetProgramImports(ctx context.Context, programSource string) (map[string]string, error) {
	imports := make(map[string]string)
	if err := c.resolveImports(ctx, programSource, imports); err != nil {
		return nil, err
	}
	return imports, nil
}

func (c *NetworkClient) resolveImports(ctx context.Context, source string, imports map[string]string) error {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		progID := strings.TrimSuffix(parts[1], ";")
		if _, exists := imports[progID]; exists {
			continue
		}

		src, err := c.GetProgram(ctx, progID)
		if err != nil {
			return fmt.Errorf("resolve import %s: %w", progID, err)
		}
		imports[progID] = src

		if err := c.resolveImports(ctx, src, imports); err != nil {
			return err
		}
	}
	return nil
}

// GetMappingValue queries a mapping value from a deployed program.
func (c *NetworkClient) GetMappingValue(ctx context.Context, programID, mappingName, key string) (string, error) {
	url := fmt.Sprintf("%s%s/program/%s/mapping/%s/%s", c.host, c.basePath(), programID, mappingName, key)
	body, err := c.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("get mapping %s/%s/%s: %w", programID, mappingName, key, err)
	}
	return string(body), nil
}

// GetTransaction fetches a transaction by ID.
func (c *NetworkClient) GetTransaction(ctx context.Context, txID string) (*Transaction, error) {
	url := fmt.Sprintf("%s%s/transaction/%s", c.host, c.basePath(), txID)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get transaction %s: %w", txID, err)
	}
	var tx Transaction
	if err := json.Unmarshal(body, &tx); err != nil {
		return nil, fmt.Errorf("decode transaction %s: %w", txID, err)
	}
	return &tx, nil
}

// GetTransactionRaw fetches a transaction by ID as raw JSON.
func (c *NetworkClient) GetTransactionRaw(ctx context.Context, txID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/transaction/%s", c.host, c.basePath(), txID)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get transaction %s: %w", txID, err)
	}
	return json.RawMessage(body), nil
}

// GetLatestBlockHeight returns the latest block height.
func (c *NetworkClient) GetLatestBlockHeight(ctx context.Context) (uint64, error) {
	url := fmt.Sprintf("%s%s/latest/height", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return 0, fmt.Errorf("get latest height: %w", err)
	}
	var height uint64
	if err := json.Unmarshal(body, &height); err != nil {
		return 0, fmt.Errorf("decode height: %w", err)
	}
	return height, nil
}

// GetLatestBlock returns the latest block.
func (c *NetworkClient) GetLatestBlock(ctx context.Context) (*Block, error) {
	url := fmt.Sprintf("%s%s/latest/block", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get latest block: %w", err)
	}
	var block Block
	if err := json.Unmarshal(body, &block); err != nil {
		return nil, fmt.Errorf("decode latest block: %w", err)
	}
	return &block, nil
}

// GetLatestHash returns the latest block hash.
func (c *NetworkClient) GetLatestHash(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s%s/latest/hash", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("get latest hash: %w", err)
	}
	return strings.Trim(string(body), "\" \n"), nil
}

// SubmitTransaction broadcasts a transaction to the network.
func (c *NetworkClient) SubmitTransaction(ctx context.Context, transaction json.RawMessage) (string, error) {
	url := fmt.Sprintf("%s%s/transaction/broadcast", c.host, c.basePath())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(transaction)))
	if err != nil {
		return "", fmt.Errorf("create broadcast request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("broadcast request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read broadcast response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("broadcast failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return strings.Trim(string(respBody), "\" \n"), nil
}

// GetPublicBalance returns the public credit balance for an address (in microcredits).
func (c *NetworkClient) GetPublicBalance(ctx context.Context, address string) (uint64, error) {
	val, err := c.GetMappingValue(ctx, "credits.aleo", "account", address)
	if err != nil {
		return 0, fmt.Errorf("get public balance: %w", err)
	}
	val = strings.TrimSpace(val)
	val = strings.Trim(val, "\"")
	val = strings.TrimSuffix(val, "u64")
	var balance uint64
	if _, err := fmt.Sscanf(val, "%d", &balance); err != nil {
		return 0, fmt.Errorf("parse balance %q: %w", val, err)
	}
	return balance, nil
}

// get performs a GET request with automatic retry on 429 and 5xx errors.
func (c *NetworkClient) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.baseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		c.applyHeaders(req)

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))

		// Retry on 429 (rate limit) and 5xx (server error)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			continue
		}

		return nil, lastErr
	}
	return nil, lastErr
}

func (c *NetworkClient) applyHeaders(req *http.Request) {
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
}
