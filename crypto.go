package sdk

import "github.com/debendraoli/provable-sdk/internal/ffi"

// ─── Hash Functions ──────────────────────────────────────────────────────────
//
// These expose SnarkVM's cryptographic hash primitives via FFI.
// Input should be an Aleo literal string (e.g. "1field", "42u64").
// Output is the resulting field element as a string.

// HashBHP256 computes a BHP256 hash of the input Aleo literal.
func HashBHP256(input string) (string, error) { return ffi.HashBHP256(input) }

// HashBHP512 computes a BHP512 hash of the input Aleo literal.
func HashBHP512(input string) (string, error) { return ffi.HashBHP512(input) }

// HashBHP768 computes a BHP768 hash of the input Aleo literal.
func HashBHP768(input string) (string, error) { return ffi.HashBHP768(input) }

// HashBHP1024 computes a BHP1024 hash of the input Aleo literal.
func HashBHP1024(input string) (string, error) { return ffi.HashBHP1024(input) }

// HashPedersen64 computes a Pedersen64 hash of the input Aleo literal.
func HashPedersen64(input string) (string, error) { return ffi.HashPedersen64(input) }

// HashPedersen128 computes a Pedersen128 hash of the input Aleo literal.
func HashPedersen128(input string) (string, error) { return ffi.HashPedersen128(input) }

// HashPoseidon2 computes a Poseidon2 hash of the input Aleo literal.
func HashPoseidon2(input string) (string, error) { return ffi.HashPoseidon2(input) }

// HashPoseidon4 computes a Poseidon4 hash of the input Aleo literal.
func HashPoseidon4(input string) (string, error) { return ffi.HashPoseidon4(input) }

// HashPoseidon8 computes a Poseidon8 hash of the input Aleo literal.
func HashPoseidon8(input string) (string, error) { return ffi.HashPoseidon8(input) }

// ─── Verification ────────────────────────────────────────────────────────────

// VerifyExecution verifies a SNARK execution proof offline without submitting
// to the network. The executionJSON should be the JSON-serialized Execution
// object from a transaction.
func VerifyExecution(executionJSON string) (bool, error) {
	return ffi.VerifyExecution(executionJSON)
}
