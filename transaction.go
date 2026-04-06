package sdk

import (
	"context"
	"encoding/json"
	"fmt"
)

// TransactionBuilder helps construct and broadcast transactions.
type TransactionBuilder struct {
	nc *NetworkClient
}

// NewTransactionBuilder creates a builder for constructing transactions.
func NewTransactionBuilder(nc *NetworkClient) *TransactionBuilder {
	return &TransactionBuilder{nc: nc}
}

// BroadcastRaw submits a pre-built transaction (as raw JSON) to the network.
func (tb *TransactionBuilder) BroadcastRaw(ctx context.Context, transaction json.RawMessage) (string, error) {
	return tb.nc.SubmitTransaction(ctx, transaction)
}

// Deploy submits an Aleo program deployment transaction.
//
// Note: Full local deployment requires offline proving support in the Rust bridge.
// For now, use the Provable DPS or CLI for deployment.
func (tb *TransactionBuilder) Deploy(ctx context.Context, programSource string) (string, error) {
	return "", fmt.Errorf("deploy: %w (use Provable DPS or CLI for deployment)", ErrNotImplemented)
}
