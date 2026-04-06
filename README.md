# aleo-go SDK

A native Go SDK for Aleo SnarkVM, providing idiomatic Go APIs for interacting with the Aleo network. Wraps SnarkVM (Rust) via CGO/FFI — no CLI subprocess needed.

## Architecture

```text
sdk/
├── rust-bridge/          # Rust cdylib crate wrapping SnarkVM
│   ├── Cargo.toml
│   └── src/lib.rs        # C-ABI functions (#[no_mangle] extern "C")
├── internal/ffi/         # Low-level CGO bindings (unexported)
│   └── bridge.go
├── account.go            # Account/key management (NewAccount, Sign, Verify)
├── authorization.go      # Authorization via snarkVM FFI (no CLI needed)
├── aleo.go               # Top-level Client struct
├── program.go            # Program execution (offline)
├── record.go             # Record decryption
├── transaction.go        # Transaction building & broadcast
├── network_client.go     # Pure Go REST client for Aleo nodes
├── program_manager.go    # ProgramManager (Provable DPS integration)
├── provable_client.go    # Provable delegated proving service client
├── types.go              # Shared types (Network, Block, Transaction, etc.)
├── errors.go             # Error definitions
├── aleo_test.go          # Tests
├── Makefile
└── README.md
```

## Prerequisites

- **Go** 1.26+
- **Rust** 1.85+ (with `cargo`)
- **C compiler** (for CGO)

## Build

```bash
# Build the Rust bridge and Go package
make build

# Build only the Rust bridge
make build-rust
```

## Performance Notes

- **`GOEXPERIMENT=jsonv2`**: Go 1.25+ includes experimental `encoding/json/v2` which provides faster JSON decoding. The SDK does heavy JSON marshaling for authorization blobs and proving requests. Enable via `GOEXPERIMENT=jsonv2 go build ./...` for better decode performance — no code changes needed.
- **`GOEXPERIMENT=runtimesecret`**: Go 1.26 has an experimental `runtime/secret` package for hardware-assisted key erasure. The SDK includes an optional `zeroize_secret.go` that uses it when this experiment is enabled.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    sdk "github.com/venture23-aleo/verulink-relayer/sdk"
)

func main() {
    // Generate a new account
    account, err := sdk.NewAccount()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Address:", account.Address())
    fmt.Println("View Key:", account.ViewKey())

    // Or from an existing private key
    account2, err := sdk.AccountFromPrivateKey("APrivateKey1zkp...")
    if err != nil {
        log.Fatal(err)
    }

    // Sign and verify messages
    sig, err := account.Sign([]byte("hello aleo"))
    if err != nil {
        log.Fatal(err)
    }

    ok, err := sdk.Verify(account.Address(), []byte("hello aleo"), sig)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Signature valid:", ok)

    // Network client
    client := sdk.NewClient("https://api.explorer.provable.com/v2", sdk.TestnetV0)

    ctx := context.Background()
    height, err := client.GetLatestBlockHeight(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Latest block height:", height)

    block, err := client.GetBlock(ctx, height)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Block hash:", block.Hash)

    // Decrypt a record
    plaintext, err := sdk.DecryptRecord("record1ciphertext...", account2.ViewKey())
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Decrypted:", plaintext)
}
```

## API Overview

### Account Management

```go
// Generate new account
account, _ := sdk.NewAccount()

// From existing key
account, _ := sdk.AccountFromPrivateKey("APrivateKey1zkp...")

// Accessors
account.Address()    // "aleo1..."
account.ViewKey()    // "AViewKey1..."
account.PrivateKey() // "APrivateKey1zkp..."

// Clear sensitive data
account.Zeroize()
```

### Signing & Verification

```go
sig, _ := account.Sign([]byte("message"))
ok, _ := sdk.Verify(account.Address(), []byte("message"), sig)
```

### Network Client

```go
client := sdk.NewClient("https://api.explorer.provable.com/v2", sdk.MainnetV0)

// Blocks
block, _ := client.GetBlock(ctx, 12345)
latest, _ := client.GetLatestBlock(ctx)
height, _ := client.GetLatestBlockHeight(ctx)

// Transactions
tx, _ := client.GetTransaction(ctx, "at1...")

// Programs
source, _ := client.GetProgram(ctx, "credits.aleo")
value, _ := client.GetMappingValue(ctx, "credits.aleo", "account", "aleo1...")

// Balance
balance, _ := client.GetPublicBalance(ctx, "aleo1...")
```

### Record Decryption

```go
plaintext, _ := sdk.DecryptRecord(ciphertext, viewKey)
```

### Program Authorization

Build a snarkVM authorization (without proof generation) via the native FFI bridge — no Leo CLI needed:

```go
nc := sdk.NewNetworkClient("https://api.explorer.provable.com/v2", sdk.MainnetV0)
auth, _ := sdk.BuildAuthorization(ctx, nc, sdk.AuthorizationOptions{
    ProgramName:  "my_program.aleo",
    FunctionName: "my_function",
    Inputs:       []string{"1u32", "2u32"},
    PrivateKey:   "APrivateKey1zkp...",
})
fmt.Println(auth.String()) // JSON authorization
```

### Provable DPS (Delegated Proving)

```go
pm, _ := sdk.NewProgramManager(sdk.ProgramManagerOptions{
    Host:       "https://api.explorer.provable.com/v2",
    Network:    sdk.TestnetV0,
    PrivateKey: "APrivateKey1zkp...",
    Provable: &sdk.ProvableConfig{
        APIKey:     "your-api-key",
        ConsumerID: "your-consumer-id",
    },
})

txID, _ := pm.ExecuteViaDPS(ctx, sdk.ProvingRequestOptions{
    ProgramName:  "my_program.aleo",
    FunctionName: "my_function",
    Inputs:       []string{"1u32", "2u32"},
    Broadcast:    true,
})
```

## Testing

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests (needs network)
make test-integration
```

## Thread Safety

- `Account` read methods (`Address()`, `ViewKey()`, `Sign()`) are safe for concurrent use.
- `NetworkClient` and `Client` methods are safe for concurrent use.
- SnarkVM proving operations are CPU-intensive. The Rust bridge handles internal synchronization.

## Supported Networks

| Constant | Value |
|----------|-------|
| `sdk.MainnetV0` | `"mainnet"` |
| `sdk.TestnetV0` | `"testnet"` |
| `sdk.CanaryV0` | `"canary"` |
