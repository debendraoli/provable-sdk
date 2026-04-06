package sdk

import (
	"encoding/json"
	"fmt"

	"github.com/debendraoli/provable-sdk/internal/ffi"
)

// ProgramID parses an Aleo instructions program and returns its program ID
// (e.g. "credits.aleo"). Uses SnarkVM FFI for validation.
func ProgramID(programSource string) (string, error) {
	return ffi.ProgramID(programSource)
}

// ExecuteOffline executes a program function offline (local synthesis + proving).
// This is CPU-intensive and may take significant time for complex programs.
//
// Parameters:
//   - programSource: full Aleo instructions source
//   - functionName: function within the program to execute
//   - inputs: Aleo-typed input strings (e.g. ["1u32", "2u32"])
//   - account: account providing the private key for authorization
//
// Returns the execution result containing transitions and proof.
func ExecuteOffline(programSource, functionName string, inputs []string, account *Account) (*ExecutionResult, error) {
	if account == nil {
		return nil, ErrNoAccount
	}

	inputsJSON, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("marshal inputs: %w", err)
	}

	resultJSON, err := ffi.ExecuteProgram(programSource, functionName, string(inputsJSON), account.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("execute program: %w", err)
	}

	return &ExecutionResult{Raw: json.RawMessage(resultJSON)}, nil
}
