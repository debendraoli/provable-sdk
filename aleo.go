package sdk

import (
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// Client provides convenient access to Aleo network operations.
// It embeds NetworkClient, so all network methods are available directly.
// For offline crypto (signing, key management), use Account directly.
// For full program lifecycle (authorization, proving, broadcast), use ProgramManager.
type Client struct {
	*NetworkClient
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithClientHTTP sets a custom HTTP client for network requests.
func WithClientHTTP(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.NetworkClient.http = httpClient
	}
}

// WithClientLogger sets a structured logger for the client.
func WithClientLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.NetworkClient.logger = logger
	}
}

// WithClientRetries configures retry behavior.
func WithClientRetries(maxRetries int, baseDelay time.Duration) ClientOption {
	return func(c *Client) {
		c.NetworkClient.maxRetries = maxRetries
		c.NetworkClient.baseDelay = baseDelay
	}
}

// WithClientRateLimit sets the maximum requests per second.
func WithClientRateLimit(reqPerSec int) ClientOption {
	return func(c *Client) {
		if reqPerSec > 0 {
			c.NetworkClient.rateLimiter = rate.NewLimiter(rate.Limit(reqPerSec), reqPerSec)
		}
	}
}

// NewClient creates a new Aleo SDK client connected to a node REST API.
//
//	host: e.g. "https://api.explorer.provable.com/v2"
//	network: MainnetV0, TestnetV0, or CanaryV0
func NewClient(host string, network Network, opts ...ClientOption) *Client {
	cl := &Client{
		NetworkClient: NewNetworkClient(host, network),
	}
	for _, o := range opts {
		o(cl)
	}
	return cl
}
