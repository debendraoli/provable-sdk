package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/debendraoli/provable-sdk/internal/ffi"
	"golang.org/x/crypto/argon2"
)

// Account represents an Aleo account with a private key, view key, and address.
// All cryptographic operations are performed via SnarkVM FFI.
//
// Account is safe to use from multiple goroutines for read operations (Address,
// ViewKey, Sign). The underlying FFI calls are stateless.
type Account struct {
	privateKey string
	viewKey    string
	computeKey string
	graphKey   string
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
// (e.g. "APrivateKey1zkp..."). The view key, compute key, graph key, and
// address are derived via SnarkVM.
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
	ck, err := ffi.PrivateKeyToComputeKey(sk)
	if err != nil {
		return nil, fmt.Errorf("derive compute key: %w", err)
	}
	gk, err := ffi.ViewKeyToGraphKey(vk)
	if err != nil {
		return nil, fmt.Errorf("derive graph key: %w", err)
	}
	a := &Account{
		privateKey: sk,
		viewKey:    vk,
		computeKey: ck,
		graphKey:   gk,
		address:    addr,
	}
	runtime.SetFinalizer(a, func(acc *Account) { acc.Zeroize() })
	return a, nil
}

// PrivateKey returns the private key string.
func (a *Account) PrivateKey() string { return a.privateKey }

// ViewKey returns the view key string.
func (a *Account) ViewKey() string { return a.viewKey }

// ComputeKey returns the compute key string.
func (a *Account) ComputeKey() string { return a.computeKey }

// GraphKey returns the graph key string.
func (a *Account) GraphKey() string { return a.graphKey }

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

// Zeroize securely clears all key material from memory by overwriting the
// underlying byte slices with zeros.
func (a *Account) Zeroize() {
	zeroString(&a.privateKey)
	zeroString(&a.viewKey)
	zeroString(&a.computeKey)
	zeroString(&a.graphKey)
	a.address = ""
}

// zeroString overwrites the backing bytes of a Go string with zeros.
// Go strings are immutable, so we use unsafe to access the backing array.
func zeroString(s *string) {
	if len(*s) == 0 {
		return
	}
	// Go string header: pointer + length. We overwrite the backing bytes.
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// ─── Password-based private key encryption ───────────────────────────────────
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
	if a.privateKey == "" {
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

	ciphertext := gcm.Seal(nil, nonce, []byte(a.privateKey), nil)

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
