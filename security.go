package sdk

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

// sealedBoxEncrypt implements libsodium's crypto_box_seal.
//
// The sealed box format is:
//
//	ephemeral_pk (32 bytes) || nacl.box(message, nonce, recipient_pk, ephemeral_sk)
//
// where nonce = BLAKE2b(ephemeral_pk || recipient_pk, output_size=24).
func sealedBoxEncrypt(recipientPK *[32]byte, message []byte) ([]byte, error) {
	// Generate an ephemeral X25519 keypair.
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	// Derive the nonce: BLAKE2b(epk || pk, no key, output_size=24).
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, fmt.Errorf("create blake2b hasher: %w", err)
	}
	_, _ = h.Write(epk[:])
	_, _ = h.Write(recipientPK[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))

	// Encrypt: nacl.box produces mac (16 bytes) || ciphertext.
	encrypted := box.Seal(nil, message, &nonce, recipientPK, esk)

	// Sealed box = ephemeral_pk || encrypted.
	result := make([]byte, 32+len(encrypted))
	copy(result[:32], epk[:])
	copy(result[32:], encrypted)

	return result, nil
}

// encryptProvingRequest encrypts a proving request's binary representation
// using the DPS's ephemeral X25519 public key, matching the Provable SDK's
// encryptProvingRequest(publicKey, provingRequest) function.
//
// publicKeyHex is the hex-encoded X25519 public key from GET /pubkey.
// data is the LE-serialized ProvingRequest bytes.
// Returns the base64-encoded sealed box ciphertext.
func encryptProvingRequest(publicKeyHex string, data []byte) (string, error) {
	pkBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("decode public key hex: %w", err)
	}
	if len(pkBytes) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pkBytes))
	}

	var pk [32]byte
	copy(pk[:], pkBytes)

	sealed, err := sealedBoxEncrypt(&pk, data)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// sealedBoxDecrypt implements libsodium's crypto_box_seal_open (for testing).
func sealedBoxDecrypt(recipientPK, recipientSK *[32]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32+box.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract ephemeral public key.
	var epk [32]byte
	copy(epk[:], ciphertext[:32])

	// Derive nonce.
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, fmt.Errorf("create blake2b hasher: %w", err)
	}
	_, _ = h.Write(epk[:])
	_, _ = h.Write(recipientPK[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))

	// Decrypt.
	plaintext, ok := box.Open(nil, ciphertext[32:], &nonce, &epk, recipientSK)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return plaintext, nil
}
