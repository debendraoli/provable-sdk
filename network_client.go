package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// NetworkClient communicates with an Aleo node's REST API (v2).
// All methods are safe for concurrent use.
type NetworkClient struct {
	host    string
	network Network
	http    *http.Client
	headers map[string]string
	logger  *slog.Logger

	// Retry configuration
	maxRetries int
	baseDelay  time.Duration

	// Rate limiting
	rateLimiter *rate.Limiter
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

// WithLogger sets a structured logger for the client.
func WithLogger(logger *slog.Logger) NetworkClientOption {
	return func(nc *NetworkClient) { nc.logger = logger }
}

// WithRateLimit sets the maximum number of requests per second.
func WithRateLimit(reqPerSec int) NetworkClientOption {
	return func(nc *NetworkClient) {
		if reqPerSec > 0 {
			nc.rateLimiter = rate.NewLimiter(rate.Limit(reqPerSec), reqPerSec)
		}
	}
}

// NewNetworkClient creates a client for the Aleo node REST API.
//
//	host: e.g. "https://api.explorer.provable.com/v2"
//	network: e.g. TestnetV0, MainnetV0
func NewNetworkClient(host string, network Network, opts ...NetworkClientOption) *NetworkClient {
	nc := &NetworkClient{
		host:    strings.TrimRight(host, "/"),
		network: network,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		},
		headers:    make(map[string]string),
		maxRetries: 3,
		baseDelay:  500 * time.Millisecond,
		logger:     slog.Default(),
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
	// The Aleo REST API returns program source as a JSON-quoted string.
	// Unquote to get the actual program text with real newlines.
	var source string
	if err := json.Unmarshal(body, &source); err != nil {
		return string(body), nil
	}
	return source, nil
}

// GetProgramImports fetches the imports of a program as a map of programID -> source.
// This recursively resolves all transitive imports using the shared collectImports logic.
func (c *NetworkClient) GetProgramImports(ctx context.Context, programSource string) (map[string]string, error) {
	imports := make(map[string]string)
	visited := make(map[string]bool)
	if err := collectImportsMap(ctx, c, nil, programSource, visited, imports); err != nil {
		return nil, err
	}
	return imports, nil
}

// GetMappingValue queries a mapping value from a deployed program.
func (c *NetworkClient) GetMappingValue(ctx context.Context, programID, mappingName, key string) (string, error) {
	url := fmt.Sprintf("%s%s/program/%s/mapping/%s/%s", c.host, c.basePath(), programID, mappingName, key)
	body, err := c.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("get mapping %s/%s/%s: %w", programID, mappingName, key, err)
	}
	var value string
	if err := json.Unmarshal(body, &value); err != nil {
		return string(body), nil
	}
	return value, nil
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

// GetStateRoot returns the latest state root.
func (c *NetworkClient) GetStateRoot(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s%s/latest/stateRoot", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("get state root: %w", err)
	}
	return strings.Trim(string(body), "\" \n"), nil
}

// GetCommittee returns the current committee/validators as raw JSON.
func (c *NetworkClient) GetCommittee(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/committee/latest", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get committee: %w", err)
	}
	return json.RawMessage(body), nil
}

// GetMempool returns pending transactions in the mempool as raw JSON.
func (c *NetworkClient) GetMempool(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/memoryPool/transactions", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get mempool: %w", err)
	}
	return json.RawMessage(body), nil
}

// GetPeers returns the connected peers as a list of addresses.
func (c *NetworkClient) GetPeers(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s%s/peers/all", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get peers: %w", err)
	}
	var peers []string
	if err := json.Unmarshal(body, &peers); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}
	return peers, nil
}

// GetPeerCount returns the number of connected peers.
func (c *NetworkClient) GetPeerCount(ctx context.Context) (int, error) {
	url := fmt.Sprintf("%s%s/peers/count", c.host, c.basePath())
	body, err := c.get(ctx, url)
	if err != nil {
		return 0, fmt.Errorf("get peer count: %w", err)
	}
	var count int
	if err := json.Unmarshal(body, &count); err != nil {
		return 0, fmt.Errorf("decode peer count: %w", err)
	}
	return count, nil
}

// GetBlockRange fetches a range of blocks by height (inclusive).
func (c *NetworkClient) GetBlockRange(ctx context.Context, start, end uint64) ([]*Block, error) {
	url := fmt.Sprintf("%s%s/blocks?start=%d&end=%d", c.host, c.basePath(), start, end)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get block range %d-%d: %w", start, end, err)
	}
	var blocks []*Block
	if err := json.Unmarshal(body, &blocks); err != nil {
		return nil, fmt.Errorf("decode block range: %w", err)
	}
	return blocks, nil
}

// GetTransactionsByBlock fetches all transactions in a block by height.
func (c *NetworkClient) GetTransactionsByBlock(ctx context.Context, height uint64) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/block/%d/transactions", c.host, c.basePath(), height)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get transactions for block %d: %w", height, err)
	}
	return json.RawMessage(body), nil
}

// SubmitTransactionDebug submits a transaction with the debug flag for verbose
// error information from the node.
func (c *NetworkClient) SubmitTransactionDebug(ctx context.Context, transaction json.RawMessage) (string, error) {
	return c.submitTransaction(ctx, transaction, true)
}

// GetStatePaths queries state paths for the given commitments against
// a consistent state root.
func (c *NetworkClient) GetStatePaths(ctx context.Context, commitments []string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/statePath", c.host, c.basePath())

	reqBody, err := json.Marshal(commitments)
	if err != nil {
		return nil, fmt.Errorf("marshal commitments: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create state path request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("state path request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read state path response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("state path failed (status %d): %s", resp.StatusCode, string(body))
	}

	return json.RawMessage(body), nil
}

// GetMappingNames returns the mapping names for a deployed program.
func (c *NetworkClient) GetMappingNames(ctx context.Context, programID string) ([]string, error) {
	url := fmt.Sprintf("%s%s/program/%s/mappings", c.host, c.basePath(), programID)
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get mappings %s: %w", programID, err)
	}
	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return nil, fmt.Errorf("decode mappings: %w", err)
	}
	return names, nil
}

// SubmitTransaction broadcasts a transaction to the network.
func (c *NetworkClient) SubmitTransaction(ctx context.Context, transaction json.RawMessage) (string, error) {
	return c.submitTransaction(ctx, transaction, false)
}

func (c *NetworkClient) submitTransaction(ctx context.Context, transaction json.RawMessage, debug bool) (string, error) {
	url := fmt.Sprintf("%s%s/transaction/broadcast", c.host, c.basePath())
	if debug {
		url += "?debug=true"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(transaction))
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
	balance, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
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
			c.logger.Debug("retrying request", "url", url, "attempt", attempt, "delay", delay)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		if c.rateLimiter != nil {
			if err := c.rateLimiter.Wait(ctx); err != nil {
				return nil, err
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
			c.logger.Warn("request failed", "url", url, "error", err)
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
			// Honor Retry-After header on 429
			if resp.StatusCode == http.StatusTooManyRequests {
				if ra := resp.Header.Get("Retry-After"); ra != "" {
					if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(time.Duration(secs) * time.Second):
						}
					}
				}
			}
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

// BlockIterator provides a streaming interface for iterating over a range of blocks.
// Blocks are prefetched in batches for efficiency.
type BlockIterator struct {
	client    *NetworkClient
	ctx       context.Context
	cur       uint64
	end       uint64
	batchSize uint64
	buf       []*Block
	bufIdx    int
	block     *Block
	err       error
}

// defaultBlockBatchSize is the number of blocks fetched per batch.
const defaultBlockBatchSize = 50

// BlockIterator creates an iterator over blocks in the range [start, end].
func (c *NetworkClient) BlockIterator(ctx context.Context, start, end uint64) *BlockIterator {
	return &BlockIterator{
		client:    c,
		ctx:       ctx,
		cur:       start,
		end:       end,
		batchSize: defaultBlockBatchSize,
	}
}

// Next advances the iterator to the next block. Returns false when done or on error.
func (it *BlockIterator) Next() bool {
	if it.err != nil {
		return false
	}

	// Serve from buffer if available.
	if it.bufIdx < len(it.buf) {
		it.block = it.buf[it.bufIdx]
		it.bufIdx++
		return true
	}

	// Check if we've exhausted the range.
	if it.cur > it.end {
		return false
	}

	// Fetch the next batch.
	batchEnd := it.cur + it.batchSize - 1
	if batchEnd > it.end {
		batchEnd = it.end
	}

	blocks, err := it.client.GetBlockRange(it.ctx, it.cur, batchEnd)
	if err != nil {
		it.err = err
		return false
	}

	it.cur = batchEnd + 1
	it.buf = blocks
	it.bufIdx = 0

	if len(blocks) == 0 {
		return false
	}
	it.block = it.buf[it.bufIdx]
	it.bufIdx++
	return true
}

// Block returns the current block.
func (it *BlockIterator) Block() *Block { return it.block }

// Err returns the first error encountered during iteration.
func (it *BlockIterator) Err() error { return it.err }

// WaitForTransaction polls for a transaction ID until it is confirmed or the
// context is cancelled. pollInterval controls how frequently to check.
func (c *NetworkClient) WaitForTransaction(ctx context.Context, txID string, pollInterval time.Duration) (*Transaction, error) {
	if pollInterval == 0 {
		pollInterval = 3 * time.Second
	}
	c.logger.Debug("waiting for transaction", "txID", txID)
	for {
		tx, err := c.GetTransaction(ctx, txID)
		if err == nil {
			return tx, nil
		}
		c.logger.Debug("transaction not found yet", "txID", txID)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
