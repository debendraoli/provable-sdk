package sdk

import (
	"context"
	"encoding/json"
	"net/http"
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
