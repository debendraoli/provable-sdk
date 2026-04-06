package sdk

import (
	"fmt"

	"github.com/debendraoli/provable-sdk/internal/ffi"
)

// Account represents an Aleo account with a private key, view key, and address.
// All cryptographic operations are performed via SnarkVM FFI.
//
// Account is safe to use from multiple goroutines for read operations (Address,
// ViewKey, Sign). The underlying FFI calls are stateless.
type Account struct {
	privateKey string
	viewKey    string
	address    string
}

// NewAccount generates a new random Aleo account (private key, view key, address).
func NewAccount() (*Account, error) {
	sk, err := ffi.PrivateKeyNew()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return accountFromSK(sk)
}

// AccountFromPrivateKey creates an Account from an existing private key string
// (e.g. "APrivateKey1zkp..."). The view key and address are derived via SnarkVM.
func AccountFromPrivateKey(privateKey string) (*Account, error) {
	if privateKey == "" {
		return nil, ErrNoPrivateKey
	}
	return accountFromSK(privateKey)
}

func accountFromSK(sk string) (*Account, error) {
	vk, err := ffi.PrivateKeyToViewKey(sk)
	if err != nil {
		return nil, fmt.Errorf("derive view key: %w", err)
	}
	addr, err := ffi.PrivateKeyToAddress(sk)
	if err != nil {
		return nil, fmt.Errorf("derive address: %w", err)
	}
	return &Account{
		privateKey: sk,
		viewKey:    vk,
		address:    addr,
	}, nil
}

// PrivateKey returns the private key string.
func (a *Account) PrivateKey() string { return a.privateKey }

// ViewKey returns the view key string.
func (a *Account) ViewKey() string { return a.viewKey }

// Address returns the Aleo address (e.g. "aleo1...").
func (a *Account) Address() string { return a.address }

// Sign signs a message with this account's private key.
// Returns the signature as a string.
func (a *Account) Sign(msg []byte) (string, error) {
	return ffi.SignMessage(a.privateKey, msg)
}

// Verify checks a signature against an address and message.
// This is a package-level function that does not require an Account.
func Verify(address string, msg []byte, signature string) (bool, error) {
	return ffi.VerifySignature(address, msg, signature)
}

// Zeroize clears the private key from memory.
func (a *Account) Zeroize() {
	b := []byte(a.privateKey)
	for i := range b {
		b[i] = 0
	}
	a.privateKey = ""
	a.viewKey = ""
	a.address = ""
}
