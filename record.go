package sdk

import "github.com/debendraoli/provable-sdk/internal/ffi"

// DecryptRecord decrypts an Aleo record ciphertext using a view key.
// The ciphertext should be the full record ciphertext string.
// Returns the plaintext record as a string.
func DecryptRecord(ciphertext, viewKey string) (string, error) {
	return ffi.DecryptRecord(ciphertext, viewKey)
}
