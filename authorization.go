package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/debendraoli/provable-sdk/internal/ffi"
)

// AuthorizationOptions configures a program authorization request.
type AuthorizationOptions struct {
	// ProgramName is the on-chain program identifier (e.g. "my_program.aleo").
	ProgramName string

	// FunctionName is the function within the program to authorize.
	FunctionName string

	// Inputs are the Aleo-typed input strings (e.g. ["1u32", "2u32"]).
	Inputs []string

	// PrivateKey overrides the account's private key for this authorization.
	// If empty, the ProgramManager's account key is used.
	PrivateKey string
}

// BuildAuthorization generates a snarkVM Authorization by calling Process::authorize
// via FFI. This produces the authorization JSON without proof generation.
//
// The NetworkClient is used to fetch the program source and any transitive imports.
func BuildAuthorization(ctx context.Context, nc *NetworkClient, opts AuthorizationOptions) (*Authorization, error) {
	if opts.PrivateKey == "" {
		return nil, ErrNoPrivateKey
	}

	// Fetch the program source from the network.
	source, err := nc.GetProgram(ctx, opts.ProgramName)
	if err != nil {
		return nil, fmt.Errorf("fetch program %s: %w", opts.ProgramName, err)
	}

	// Resolve transitive imports (excluding credits.aleo, which is built-in).
	importSources, err := resolveImportsOrdered(ctx, nc, source)
	if err != nil {
		return nil, fmt.Errorf("resolve imports: %w", err)
	}

	// Serialize inputs and imports as JSON for FFI.
	inputsJSON, err := json.Marshal(opts.Inputs)
	if err != nil {
		return nil, fmt.Errorf("marshal inputs: %w", err)
	}
	importsJSON, err := json.Marshal(importSources)
	if err != nil {
		return nil, fmt.Errorf("marshal imports: %w", err)
	}

	// Call snarkVM Process::authorize via FFI.
	authJSON, err := ffi.Authorize(opts.PrivateKey, source, opts.FunctionName, string(inputsJSON), string(importsJSON))
	if err != nil {
		return nil, fmt.Errorf("authorize %s/%s: %w", opts.ProgramName, opts.FunctionName, err)
	}

	return &Authorization{Raw: json.RawMessage(authJSON)}, nil
}

// resolveImportsOrdered fetches all transitive imports for a program source,
// returning their source strings in dependency order (leaves first).
// credits.aleo is excluded since it's built into the Process.
func resolveImportsOrdered(ctx context.Context, nc *NetworkClient, source string) ([]string, error) {
	ordered := make([]string, 0)
	visited := make(map[string]bool)
	if err := collectImports(ctx, nc, source, visited, &ordered); err != nil {
		return nil, err
	}
	return ordered, nil
}

func collectImports(ctx context.Context, nc *NetworkClient, source string, visited map[string]bool, ordered *[]string) error {
	for line := range strings.SplitSeq(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		progID := strings.TrimSuffix(parts[1], ";")

		// Skip if already visited or if it's the built-in credits program.
		if visited[progID] || progID == "credits.aleo" {
			continue
		}
		visited[progID] = true

		impSrc, err := nc.GetProgram(ctx, progID)
		if err != nil {
			return fmt.Errorf("fetch import %s: %w", progID, err)
		}

		// Recurse into this import's dependencies first (depth-first).
		if err := collectImports(ctx, nc, impSrc, visited, ordered); err != nil {
			return err
		}

		// Add after dependencies are resolved (topological order).
		*ordered = append(*ordered, impSrc)
	}
	return nil
}
