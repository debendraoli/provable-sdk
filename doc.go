// Package sdk provides an idiomatic Go SDK for the Aleo network, wrapping
// SnarkVM via Rust FFI (CGO) for cryptographic operations and providing a
// pure-Go REST client for network interaction.
//
// Architecture:
//   - Rust bridge (rust-bridge/): thin cdylib exposing SnarkVM as C-ABI functions
//   - internal/ffi: low-level CGO bindings (unexported)
//   - Public API: Account for key/signing, Client/NetworkClient for REST, ProgramManager for DPS
//
// Quick start:
//
//	// Generate a new account
//	account, err := sdk.NewAccount()
//	if err != nil { ... }
//	fmt.Println(account.Address()) // aleo1...
//
//	// Sign and verify
//	sig, _ := account.Sign([]byte("hello"))
//	ok, _ := sdk.Verify(account.Address(), []byte("hello"), sig)
//
//	// Network client (v2 API)
//	client := sdk.NewClient("https://api.explorer.provable.com/v2", sdk.TestnetV0)
//	block, _ := client.GetBlock(ctx, 12345)
//
//	// Decrypt a record
//	plaintext, _ := sdk.DecryptRecord(ciphertext, account.ViewKey())
package sdk
