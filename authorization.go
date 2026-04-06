package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/debendraoli/provable-sdk/internal/ffi"
)

// AuthorizationOptions is an alias for ProvingRequestOptions.
//
// Deprecated: Use ProvingRequestOptions directly.
type AuthorizationOptions = ProvingRequestOptions

// BuildAuthorization generates a snarkVM Authorization by calling Process::authorize
// via FFI. This produces the authorization JSON without proof generation.
//
// The NetworkClient is used to fetch the program source and any transitive imports.
func BuildAuthorization(ctx context.Context, nc *NetworkClient, opts ProvingRequestOptions) (*Authorization, error) {
	return BuildAuthorizationWithCache(ctx, nc, nil, opts)
}

// BuildAuthorizationWithCache is like BuildAuthorization but caches program source
// in the provided sync.Map (keyed by program ID). If cache is nil, no caching is performed.
func BuildAuthorizationWithCache(ctx context.Context, nc *NetworkClient, cache *sync.Map, opts ProvingRequestOptions) (*Authorization, error) {
	if opts.PrivateKey == "" {
		return nil, ErrNoPrivateKey
	}

	// Fetch the program source from cache or network.
	source, err := fetchProgramCached(ctx, nc, cache, opts.ProgramName)
	if err != nil {
		return nil, fmt.Errorf("fetch program %s: %w", opts.ProgramName, err)
	}

	// Resolve transitive imports (excluding credits.aleo, which is built-in).
	importSources, err := resolveImportsOrdered(ctx, nc, cache, source)
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
func resolveImportsOrdered(ctx context.Context, nc *NetworkClient, cache *sync.Map, source string) ([]string, error) {
	ordered := make([]string, 0)
	visited := make(map[string]bool)
	if err := collectImports(ctx, nc, cache, source, visited, &ordered); err != nil {
		return nil, err
	}
	return ordered, nil
}

func collectImports(ctx context.Context, nc *NetworkClient, cache *sync.Map, source string, visited map[string]bool, ordered *[]string) error {
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

		impSrc, err := fetchProgramCached(ctx, nc, cache, progID)
		if err != nil {
			return fmt.Errorf("fetch import %s: %w", progID, err)
		}

		// Recurse into this import's dependencies first (depth-first).
		if err := collectImports(ctx, nc, cache, impSrc, visited, ordered); err != nil {
			return err
		}

		// Add after dependencies are resolved (topological order).
		*ordered = append(*ordered, impSrc)
	}
	return nil
}

// collectImportsMap is like collectImports but builds a map of programID -> source.
func collectImportsMap(ctx context.Context, nc *NetworkClient, cache *sync.Map, source string, visited map[string]bool, imports map[string]string) error {
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

		if visited[progID] || progID == "credits.aleo" {
			continue
		}
		visited[progID] = true

		impSrc, err := fetchProgramCached(ctx, nc, cache, progID)
		if err != nil {
			return fmt.Errorf("fetch import %s: %w", progID, err)
		}

		if err := collectImportsMap(ctx, nc, cache, impSrc, visited, imports); err != nil {
			return err
		}

		imports[progID] = impSrc
	}
	return nil
}

// fetchProgramCached fetches program source from cache or network.
// If cache is nil, always fetches from network.
func fetchProgramCached(ctx context.Context, nc *NetworkClient, cache *sync.Map, programID string) (string, error) {
	if cache != nil {
		if v, ok := cache.Load(programID); ok {
			return v.(string), nil
		}
	}
	src, err := nc.GetProgram(ctx, programID)
	if err != nil {
		return "", err
	}
	if cache != nil {
		cache.Store(programID, src)
	}
	return src, nil
}
