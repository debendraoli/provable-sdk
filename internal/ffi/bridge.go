package ffi

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust-bridge/target/release -laleo_bridge -ldl -lm -lpthread
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -I${SRCDIR}/../../rust-bridge

#include <stdlib.h>
#include <stdint.h>

// Account / key management
extern char* aleo_private_key_new();
extern char* aleo_derive_all_keys(const char* sk);

// Signing / verification
extern char* aleo_sign_message(const char* sk, const void* msg, size_t msg_len);
extern int   aleo_verify_signature(const char* addr, const void* msg, size_t msg_len, const char* sig);

// Record decryption
extern char* aleo_decrypt_record(const char* ciphertext, const char* vk);

// Program operations
extern char* aleo_execute_program(const char* program_source, const char* function_name, const char* inputs_json, const char* sk);
extern char* aleo_program_id(const char* program_source);

// Authorization
extern char* aleo_authorize(const char* private_key, const char* program_source, const char* function_name, const char* inputs_json, const char* imports_json);
extern char* aleo_proving_request_to_bytes(const char* auth_json, const char* fee_auth_json, _Bool broadcast);

// Hash functions
extern char* aleo_hash_bhp256(const char* input);
extern char* aleo_hash_bhp512(const char* input);
extern char* aleo_hash_bhp768(const char* input);
extern char* aleo_hash_bhp1024(const char* input);
extern char* aleo_hash_ped64(const char* input);
extern char* aleo_hash_ped128(const char* input);
extern char* aleo_hash_psd2(const char* input);
extern char* aleo_hash_psd4(const char* input);
extern char* aleo_hash_psd8(const char* input);
extern char* aleo_hash_psd2_multi(const char* inputs_json);
extern char* aleo_hash_psd4_multi(const char* inputs_json);
extern char* aleo_hash_psd8_multi(const char* inputs_json);

// Verification
extern char* aleo_verify_execution(const char* execution_json);

// Memory management
extern void aleo_free_string(char* ptr);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// resultOrError reads a C string returned by the Rust bridge and translates
// the `{"error":"..."}` convention into a Go error.
func resultOrError(cstr *C.char) (string, error) {
	if cstr == nil {
		return "", fmt.Errorf("bridge returned nil")
	}
	defer C.aleo_free_string(cstr)

	s := C.GoString(cstr)

	// The Rust bridge signals errors with a JSON payload: {"error":"..."}
	const errPrefix = `{"error":"`
	if len(s) > len(errPrefix) && s[:len(errPrefix)] == errPrefix {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(s), &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("%s", errResp.Error)
		}
	}
	return s, nil
}

// PrivateKeyNew generates a new random Aleo private key via FFI.
func PrivateKeyNew() (string, error) {
	return resultOrError(C.aleo_private_key_new())
}

// SignMessage signs a byte message with a private key via FFI.
func SignMessage(sk string, msg []byte) (string, error) {
	csk := C.CString(sk)
	defer C.free(unsafe.Pointer(csk))

	var msgPtr unsafe.Pointer
	if len(msg) > 0 {
		msgPtr = unsafe.Pointer(&msg[0])
	}

	return resultOrError(C.aleo_sign_message(csk, msgPtr, C.size_t(len(msg))))
}

// VerifySignature checks a signature against an address and message via FFI.
func VerifySignature(addr string, msg []byte, sig string) (bool, error) {
	caddr := C.CString(addr)
	defer C.free(unsafe.Pointer(caddr))
	csig := C.CString(sig)
	defer C.free(unsafe.Pointer(csig))

	var msgPtr unsafe.Pointer
	if len(msg) > 0 {
		msgPtr = unsafe.Pointer(&msg[0])
	}

	result := C.aleo_verify_signature(caddr, msgPtr, C.size_t(len(msg)), csig)
	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, fmt.Errorf("signature verification failed (internal error)")
	}
}

// DecryptRecord decrypts a record ciphertext with a view key via FFI.
func DecryptRecord(ciphertext, viewKey string) (string, error) {
	cct := C.CString(ciphertext)
	defer C.free(unsafe.Pointer(cct))
	cvk := C.CString(viewKey)
	defer C.free(unsafe.Pointer(cvk))

	return resultOrError(C.aleo_decrypt_record(cct, cvk))
}

// ExecuteProgram runs offline program execution via FFI.
func ExecuteProgram(programSource, functionName, inputsJSON, sk string) (string, error) {
	csrc := C.CString(programSource)
	defer C.free(unsafe.Pointer(csrc))
	cfn := C.CString(functionName)
	defer C.free(unsafe.Pointer(cfn))
	cinputs := C.CString(inputsJSON)
	defer C.free(unsafe.Pointer(cinputs))
	csk := C.CString(sk)
	defer C.free(unsafe.Pointer(csk))

	return resultOrError(C.aleo_execute_program(csrc, cfn, cinputs, csk))
}

// ProgramID parses a program and returns its ID via FFI.
func ProgramID(programSource string) (string, error) {
	csrc := C.CString(programSource)
	defer C.free(unsafe.Pointer(csrc))
	return resultOrError(C.aleo_program_id(csrc))
}

// ProvingRequestToBytes serializes a ProvingRequest to LE bytes matching the Provable SDK wire format.
// Returns base64-encoded bytes. feeAuthJSON may be empty for no fee authorization.
func ProvingRequestToBytes(authJSON, feeAuthJSON string, broadcast bool) (string, error) {
	cAuth := C.CString(authJSON)
	defer C.free(unsafe.Pointer(cAuth))

	var cFee *C.char
	if feeAuthJSON != "" {
		cFee = C.CString(feeAuthJSON)
		defer C.free(unsafe.Pointer(cFee))
	}

	return resultOrError(C.aleo_proving_request_to_bytes(cAuth, cFee, C._Bool(broadcast)))
}

// Authorize builds a snarkVM Authorization via Process::authorize (no proof generation).
// programSource is the Aleo instructions for the target program.
// inputsJSON is a JSON array of input strings.
// importsJSON is a JSON array of import program source strings (in dependency order, excluding credits.aleo).
func Authorize(privateKey, programSource, functionName, inputsJSON, importsJSON string) (string, error) {
	csk := C.CString(privateKey)
	defer C.free(unsafe.Pointer(csk))
	csrc := C.CString(programSource)
	defer C.free(unsafe.Pointer(csrc))
	cfn := C.CString(functionName)
	defer C.free(unsafe.Pointer(cfn))
	cinputs := C.CString(inputsJSON)
	defer C.free(unsafe.Pointer(cinputs))
	cimports := C.CString(importsJSON)
	defer C.free(unsafe.Pointer(cimports))
	return resultOrError(C.aleo_authorize(csk, csrc, cfn, cinputs, cimports))
}

// DeriveAllKeys derives view key, address, compute key, and graph key from a
// private key in a single FFI call. Returns the JSON string.
func DeriveAllKeys(sk string) (string, error) {
	csk := C.CString(sk)
	defer C.free(unsafe.Pointer(csk))
	return resultOrError(C.aleo_derive_all_keys(csk))
}

// HashBHP256 computes a BHP256 hash of the input literal.
func HashBHP256(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_bhp256(cinput))
}

// HashBHP512 computes a BHP512 hash of the input literal.
func HashBHP512(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_bhp512(cinput))
}

// HashBHP768 computes a BHP768 hash of the input literal.
func HashBHP768(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_bhp768(cinput))
}

// HashBHP1024 computes a BHP1024 hash of the input literal.
func HashBHP1024(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_bhp1024(cinput))
}

// HashPedersen64 computes a Pedersen64 hash of the input literal.
func HashPedersen64(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_ped64(cinput))
}

// HashPedersen128 computes a Pedersen128 hash of the input literal.
func HashPedersen128(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_ped128(cinput))
}

// HashPoseidon2 computes a Poseidon2 hash of the input literal.
func HashPoseidon2(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_psd2(cinput))
}

// HashPoseidon4 computes a Poseidon4 hash of the input literal.
func HashPoseidon4(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_psd4(cinput))
}

// HashPoseidon8 computes a Poseidon8 hash of the input literal.
func HashPoseidon8(input string) (string, error) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))
	return resultOrError(C.aleo_hash_psd8(cinput))
}

// HashPoseidon2Multi computes a Poseidon2 hash of multiple input literals.
func HashPoseidon2Multi(inputsJSON string) (string, error) {
	cinputs := C.CString(inputsJSON)
	defer C.free(unsafe.Pointer(cinputs))
	return resultOrError(C.aleo_hash_psd2_multi(cinputs))
}

// HashPoseidon4Multi computes a Poseidon4 hash of multiple input literals.
func HashPoseidon4Multi(inputsJSON string) (string, error) {
	cinputs := C.CString(inputsJSON)
	defer C.free(unsafe.Pointer(cinputs))
	return resultOrError(C.aleo_hash_psd4_multi(cinputs))
}

// HashPoseidon8Multi computes a Poseidon8 hash of multiple input literals.
func HashPoseidon8Multi(inputsJSON string) (string, error) {
	cinputs := C.CString(inputsJSON)
	defer C.free(unsafe.Pointer(cinputs))
	return resultOrError(C.aleo_hash_psd8_multi(cinputs))
}

// VerifyExecution verifies a SNARK execution proof offline.
func VerifyExecution(executionJSON string) (bool, error) {
	cjson := C.CString(executionJSON)
	defer C.free(unsafe.Pointer(cjson))
	result, err := resultOrError(C.aleo_verify_execution(cjson))
	if err != nil {
		return false, err
	}
	return result == "true", nil
}
