package sdk

import "errors"

var (
	// ErrEmptyTransaction is returned when a proving response contains no transaction.
	ErrEmptyTransaction = errors.New("empty transaction in proving response")

	// ErrEmptyTransactionID is returned when the transaction JSON has no "id" field.
	ErrEmptyTransactionID = errors.New("transaction ID is empty in proving response")

	// ErrNoPrivateKey is returned when an operation requires a private key but none is set.
	ErrNoPrivateKey = errors.New("no private key configured")

	// ErrAuthorizationFailed is returned when authorization produces no valid output.
	ErrAuthorizationFailed = errors.New("authorization produced no valid JSON")

	// ErrNoAccount is returned when an operation requires an account but none is set.
	ErrNoAccount = errors.New("no account configured")

	// ErrInvalidSignature is returned when a signature verification fails due to internal error.
	ErrInvalidSignature = errors.New("signature verification failed")

	// ErrDecryptionFailed is returned when record decryption fails.
	ErrDecryptionFailed = errors.New("record decryption failed")

	// ErrNotImplemented is returned for features not yet available.
	ErrNotImplemented = errors.New("not implemented")

	// ErrProvableClientNotConfigured is returned when DPS methods are called without a ProvableClient.
	ErrProvableClientNotConfigured = errors.New("provable client not configured")

	// ErrProvingFailed is returned when the DPS returns a non-success HTTP status.
	ErrProvingFailed = errors.New("proving request failed")
)
