package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/debendraoli/provable-sdk/internal/ffi"
	"golang.org/x/crypto/argon2"
)

// Account represents an Aleo account with a private key, view key, and address.
// All cryptographic operations are performed via SnarkVM FFI.
//
// Account is safe to use from multiple goroutines for read operations (Address,
// ViewKey, Sign). The underlying FFI calls are stateless.
type Account struct {
	privateKey []byte
	viewKey    []byte
	computeKey []byte
	graphKey   []byte
	address    string // address is public, no need to zeroize
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
// (e.g. "APrivateKey1zkp..."). The view key, compute key, graph key, and
// address are derived via SnarkVM.
func AccountFromPrivateKey(privateKey string) (*Account, error) {
	if privateKey == "" {
		return nil, ErrNoPrivateKey
	}
	return accountFromSK(privateKey)
}

func accountFromSK(sk string) (*Account, error) {
	keysJSON, err := ffi.DeriveAllKeys(sk)
	if err != nil {
		return nil, fmt.Errorf("derive keys: %w", err)
	}
	var keys struct {
		ViewKey    string          `json:"view_key"`
		Address    string          `json:"address"`
		ComputeKey json.RawMessage `json:"compute_key"`
		GraphKey   string          `json:"graph_key"`
	}
	if err := json.Unmarshal([]byte(keysJSON), &keys); err != nil {
		return nil, fmt.Errorf("parse derived keys: %w", err)
	}
	a := &Account{
		privateKey: []byte(sk),
		viewKey:    []byte(keys.ViewKey),
		computeKey: keys.ComputeKey,
		graphKey:   []byte(keys.GraphKey),
		address:    keys.Address,
	}
	runtime.SetFinalizer(a, func(acc *Account) { acc.Zeroize() })
	return a, nil
}

// PrivateKey returns the private key string.
func (a *Account) PrivateKey() string { return string(a.privateKey) }

// ViewKey returns the view key string.
func (a *Account) ViewKey() string { return string(a.viewKey) }

// ComputeKey returns the compute key string.
func (a *Account) ComputeKey() string { return string(a.computeKey) }

// GraphKey returns the graph key string.
func (a *Account) GraphKey() string { return string(a.graphKey) }

// Address returns the Aleo address (e.g. "aleo1...").
func (a *Account) Address() string { return a.address }

// Sign signs a message with this account's private key.
// Returns the signature as a string.
func (a *Account) Sign(msg []byte) (string, error) {
	return ffi.SignMessage(string(a.privateKey), msg)
}

// Verify checks a signature against an address and message.
// This is a package-level function that does not require an Account.
func Verify(address string, msg []byte, signature string) (bool, error) {
	return ffi.VerifySignature(address, msg, signature)
}

// Zeroize securely clears all key material from memory by overwriting the
// underlying byte slices with zeros.
func (a *Account) Zeroize() {
	for i := range a.privateKey {
		a.privateKey[i] = 0
	}
	for i := range a.viewKey {
		a.viewKey[i] = 0
	}
	for i := range a.computeKey {
		a.computeKey[i] = 0
	}
	for i := range a.graphKey {
		a.graphKey[i] = 0
	}
	a.privateKey = nil
	a.viewKey = nil
	a.computeKey = nil
	a.graphKey = nil
	a.address = ""
}

//
// Uses Argon2id for key derivation and AES-256-GCM for encryption,
// matching the JS SDK's Encryptor pattern.

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// EncryptPrivateKey encrypts this account's private key with a password.
// Returns a base64-encoded ciphertext that can be decrypted with
// AccountFromEncryptedPrivateKey.
func (a *Account) EncryptPrivateKey(password string) (string, error) {
	if a.privateKey == nil {
		return "", ErrNoPrivateKey
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, a.privateKey, nil)

	// Format: salt || nonce || ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// AccountFromEncryptedPrivateKey decrypts a private key from an encrypted
// payload produced by Account.EncryptPrivateKey and creates a new Account.
func AccountFromEncryptedPrivateKey(encrypted, password string) (*Account, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}

	if len(data) < argon2SaltLen+12 { // minimum: salt + nonce (GCM nonce = 12)
		return nil, fmt.Errorf("encrypted data too short")
	}

	salt := data[:argon2SaltLen]
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < argon2SaltLen+nonceSize {
		return nil, fmt.Errorf("encrypted data too short for nonce")
	}
	nonce := data[argon2SaltLen : argon2SaltLen+nonceSize]
	ciphertext := data[argon2SaltLen+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	defer zeroBytes(plaintext)

	return AccountFromPrivateKey(string(plaintext))
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
