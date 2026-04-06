package sdk

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// Client provides convenient access to Aleo network operations.
// For offline crypto (signing, key management), use Account directly.
// For full program lifecycle (authorization, proving, broadcast), use ProgramManager.
type Client struct {
	nc *NetworkClient
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithClientHTTP sets a custom HTTP client for network requests.
func WithClientHTTP(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.nc.http = httpClient
	}
}

// WithClientLogger sets a structured logger for the client.
func WithClientLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.nc.logger = logger
	}
}

// WithClientRetries configures retry behavior.
func WithClientRetries(maxRetries int, baseDelay time.Duration) ClientOption {
	return func(c *Client) {
		c.nc.maxRetries = maxRetries
		c.nc.baseDelay = baseDelay
	}
}

// WithClientRateLimit sets the maximum requests per second.
func WithClientRateLimit(reqPerSec int) ClientOption {
	return func(c *Client) {
		if reqPerSec > 0 {
			c.nc.rateLimiter = newRateLimiter(reqPerSec)
		}
	}
}

// NewClient creates a new Aleo SDK client connected to a node REST API.
//
//	host: e.g. "https://api.explorer.provable.com/v2"
//	network: MainnetV0, TestnetV0, or CanaryV0
func NewClient(host string, network Network, opts ...ClientOption) *Client {
	cl := &Client{
		nc: NewNetworkClient(host, network),
	}
	for _, o := range opts {
		o(cl)
	}
	return cl
}

// NetworkClient returns the underlying network client for advanced use.
func (c *Client) NetworkClient() *NetworkClient { return c.nc }

// ─── Network queries ─────────────────────────────────────────────────────────

// GetBlock fetches a block by height.
func (c *Client) GetBlock(ctx context.Context, height uint64) (*Block, error) {
	return c.nc.GetBlock(ctx, height)
}

// GetLatestBlock returns the latest block.
func (c *Client) GetLatestBlock(ctx context.Context) (*Block, error) {
	return c.nc.GetLatestBlock(ctx)
}

// GetLatestBlockHeight returns the latest block height.
func (c *Client) GetLatestBlockHeight(ctx context.Context) (uint64, error) {
	return c.nc.GetLatestBlockHeight(ctx)
}

// GetTransaction fetches a transaction by ID.
func (c *Client) GetTransaction(ctx context.Context, txID string) (*Transaction, error) {
	return c.nc.GetTransaction(ctx, txID)
}

// GetProgram fetches the source of a deployed program.
func (c *Client) GetProgram(ctx context.Context, programID string) (string, error) {
	return c.nc.GetProgram(ctx, programID)
}

// GetMappingValue queries a mapping value from a deployed program.
func (c *Client) GetMappingValue(ctx context.Context, programID, mappingName, key string) (string, error) {
	return c.nc.GetMappingValue(ctx, programID, mappingName, key)
}

// GetPublicBalance returns the public credit balance for an address (microcredits).
func (c *Client) GetPublicBalance(ctx context.Context, address string) (uint64, error) {
	return c.nc.GetPublicBalance(ctx, address)
}

// Broadcast submits a completed transaction to the network.
func (c *Client) Broadcast(ctx context.Context, transaction json.RawMessage) (string, error) {
	return c.nc.SubmitTransaction(ctx, transaction)
}

// GetStateRoot returns the latest state root.
func (c *Client) GetStateRoot(ctx context.Context) (string, error) {
	return c.nc.GetStateRoot(ctx)
}

// GetCommittee returns the current committee/validators.
func (c *Client) GetCommittee(ctx context.Context) (json.RawMessage, error) {
	return c.nc.GetCommittee(ctx)
}

// GetMempool returns pending transactions in the mempool.
func (c *Client) GetMempool(ctx context.Context) (json.RawMessage, error) {
	return c.nc.GetMempool(ctx)
}

// GetPeers returns connected peer addresses.
func (c *Client) GetPeers(ctx context.Context) ([]string, error) {
	return c.nc.GetPeers(ctx)
}

// GetPeerCount returns the number of connected peers.
func (c *Client) GetPeerCount(ctx context.Context) (int, error) {
	return c.nc.GetPeerCount(ctx)
}

// GetBlockRange fetches a range of blocks by height.
func (c *Client) GetBlockRange(ctx context.Context, start, end uint64) ([]*Block, error) {
	return c.nc.GetBlockRange(ctx, start, end)
}

// GetTransactionsByBlock fetches all transactions in a block.
func (c *Client) GetTransactionsByBlock(ctx context.Context, height uint64) (json.RawMessage, error) {
	return c.nc.GetTransactionsByBlock(ctx, height)
}

// WaitForTransaction polls until a transaction is confirmed.
func (c *Client) WaitForTransaction(ctx context.Context, txID string, pollInterval time.Duration) (*Transaction, error) {
	return c.nc.WaitForTransaction(ctx, txID, pollInterval)
}

// BlockIterator creates an iterator over blocks in a range.
func (c *Client) BlockIterator(ctx context.Context, start, end uint64) *BlockIterator {
	return c.nc.BlockIterator(ctx, start, end)
}
