package sdk

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// ─── Unit tests ──────────────────────────────────────────────────────────────

func TestNewAccount(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	if account.PrivateKey() == "" {
		t.Error("PrivateKey() is empty")
	}
	if account.ViewKey() == "" {
		t.Error("ViewKey() is empty")
	}
	if account.Address() == "" {
		t.Error("Address() is empty")
	}
	if len(account.Address()) < 5 || account.Address()[:5] != "aleo1" {
		t.Errorf("Address() = %q, want prefix 'aleo1'", account.Address())
	}
}

func TestAccountFromPrivateKey(t *testing.T) {
	account1, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	account2, err := AccountFromPrivateKey(account1.PrivateKey())
	if err != nil {
		t.Fatalf("AccountFromPrivateKey() error: %v", err)
	}
	if account1.Address() != account2.Address() {
		t.Errorf("Address mismatch: %s != %s", account1.Address(), account2.Address())
	}
	if account1.ViewKey() != account2.ViewKey() {
		t.Errorf("ViewKey mismatch: %s != %s", account1.ViewKey(), account2.ViewKey())
	}
}

func TestAccountFromPrivateKey_Empty(t *testing.T) {
	_, err := AccountFromPrivateKey("")
	if err == nil {
		t.Error("AccountFromPrivateKey(\"\") should return error")
	}
}

func TestAccountFromPrivateKey_Invalid(t *testing.T) {
	_, err := AccountFromPrivateKey("not-a-real-key")
	if err == nil {
		t.Error("AccountFromPrivateKey(invalid) should return error")
	}
}

func TestSignAndVerify(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	msg := []byte("hello aleo")
	sig, err := account.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if sig == "" {
		t.Fatal("Sign() returned empty signature")
	}
	ok, err := Verify(account.Address(), msg, sig)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("Verify() = false, want true")
	}
}

func TestVerify_WrongMessage(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	sig, err := account.Sign([]byte("hello"))
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	ok, err := Verify(account.Address(), []byte("world"), sig)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if ok {
		t.Error("Verify() = true for wrong message, want false")
	}
}

func TestVerify_WrongAddress(t *testing.T) {
	account1, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	account2, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	msg := []byte("hello")
	sig, err := account1.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	ok, err := Verify(account2.Address(), msg, sig)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if ok {
		t.Error("Verify() = true for wrong address, want false")
	}
}

func TestSignAndVerify_EmptyMessage(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	sig, err := account.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign(empty) error: %v", err)
	}
	ok, err := Verify(account.Address(), []byte{}, sig)
	if err != nil {
		t.Fatalf("Verify(empty) error: %v", err)
	}
	if !ok {
		t.Error("Verify(empty) = false, want true")
	}
}

func TestZeroize(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	account.Zeroize()
	if account.PrivateKey() != "" {
		t.Error("PrivateKey not zeroized")
	}
	if account.ViewKey() != "" {
		t.Error("ViewKey not zeroized")
	}
	if account.Address() != "" {
		t.Error("Address not zeroized")
	}
}

func TestNetworkTypes(t *testing.T) {
	tests := []struct {
		n    Network
		want string
	}{
		{MainnetV0, "mainnet"},
		{TestnetV0, "testnet"},
		{CanaryV0, "canary"},
	}
	for _, tt := range tests {
		if tt.n.String() != tt.want {
			t.Errorf("%v.String() = %q, want %q", tt.n, tt.n.String(), tt.want)
		}
		if !tt.n.Valid() {
			t.Errorf("%v.Valid() = false, want true", tt.n)
		}
	}
	if Network("invalid").Valid() {
		t.Error("Network(\"invalid\").Valid() = true, want false")
	}
}

// ─── Network client tests (httptest) ─────────────────────────────────────────

func newTestServer(handler http.HandlerFunc) (*httptest.Server, *NetworkClient) {
	srv := httptest.NewServer(handler)
	client := NewNetworkClient(srv.URL, TestnetV0, WithRetry(0, 0))
	return srv, client
}

func TestNetworkClient_GetLatestBlockHeight(t *testing.T) {
	srv, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/latest/height" {
			_, _ = w.Write([]byte("42"))
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	height, err := client.GetLatestBlockHeight(context.Background())
	if err != nil {
		t.Fatalf("GetLatestBlockHeight() error: %v", err)
	}
	if height != 42 {
		t.Errorf("GetLatestBlockHeight() = %d, want 42", height)
	}
}

func TestNetworkClient_GetProgram(t *testing.T) {
	srv, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/program/credits.aleo" {
			_, _ = w.Write([]byte("program credits.aleo;"))
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	src, err := client.GetProgram(context.Background(), "credits.aleo")
	if err != nil {
		t.Fatalf("GetProgram() error: %v", err)
	}
	if src != "program credits.aleo;" {
		t.Errorf("GetProgram() = %q", src)
	}
}

func TestNetworkClient_GetTransaction(t *testing.T) {
	srv, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/transaction/at1test" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"type":"execute","id":"at1test"}`))
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	tx, err := client.GetTransaction(context.Background(), "at1test")
	if err != nil {
		t.Fatalf("GetTransaction() error: %v", err)
	}
	if tx.ID != "at1test" {
		t.Errorf("GetTransaction().ID = %q, want 'at1test'", tx.ID)
	}
}

func TestNetworkClient_GetBlock(t *testing.T) {
	srv, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/block/100" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"block_hash":"ab1abc","previous_hash":"ab1def","header":{}}`))
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	block, err := client.GetBlock(context.Background(), 100)
	if err != nil {
		t.Fatalf("GetBlock() error: %v", err)
	}
	if block.Hash != "ab1abc" {
		t.Errorf("GetBlock().Hash = %q, want 'ab1abc'", block.Hash)
	}
}

func TestNetworkClient_GetPublicBalance(t *testing.T) {
	srv, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/program/credits.aleo/mapping/account/aleo1test" {
			_, _ = w.Write([]byte(`"5000000u64"`))
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	balance, err := client.GetPublicBalance(context.Background(), "aleo1test")
	if err != nil {
		t.Fatalf("GetPublicBalance() error: %v", err)
	}
	if balance != 5000000 {
		t.Errorf("GetPublicBalance() = %d, want 5000000", balance)
	}
}

func TestClient_Convenience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testnet/latest/height" {
			_, _ = w.Write([]byte("999"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client := NewClient(srv.URL, TestnetV0)
	height, err := client.GetLatestBlockHeight(context.Background())
	if err != nil {
		t.Fatalf("Client.GetLatestBlockHeight() error: %v", err)
	}
	if height != 999 {
		t.Errorf("Client.GetLatestBlockHeight() = %d, want 999", height)
	}
}

func TestNetworkClient_RetryOn429(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		_, _ = w.Write([]byte("42"))
	}))
	defer srv.Close()
	client := NewNetworkClient(srv.URL, TestnetV0, WithRetry(3, 10*time.Millisecond))
	height, err := client.GetLatestBlockHeight(context.Background())
	if err != nil {
		t.Fatalf("GetLatestBlockHeight() error after retry: %v", err)
	}
	if height != 42 {
		t.Errorf("height = %d, want 42", height)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestResolveImportsOrdered(t *testing.T) {
	// Simulate a node serving two programs: child.aleo imports credits.aleo, parent.aleo imports child.aleo.
	childSrc := "import credits.aleo;\nprogram child.aleo;\nfunction main:\n    input r0 as u32.public;\n    output r0 as u32.public;\n"
	parentSrc := "import child.aleo;\nprogram parent.aleo;\nfunction main:\n    input r0 as u32.public;\n    output r0 as u32.public;\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/testnet/program/child.aleo":
			_, _ = w.Write([]byte(childSrc))
		case "/testnet/program/parent.aleo":
			_, _ = w.Write([]byte(parentSrc))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	nc := NewNetworkClient(srv.URL, TestnetV0, WithRetry(0, 0))
	imports, err := resolveImportsOrdered(context.Background(), nc, nil, parentSrc)
	if err != nil {
		t.Fatalf("resolveImportsOrdered() error: %v", err)
	}
	// child.aleo should come first (dependency), credits.aleo excluded.
	if len(imports) != 1 {
		t.Fatalf("len(imports) = %d, want 1", len(imports))
	}
	if imports[0] != childSrc {
		t.Errorf("imports[0] = %q, want child source", imports[0])
	}
}

// ─── Sealed box encryption tests ─────────────────────────────────────────────

func TestSealedBoxEncryptDecrypt(t *testing.T) {
	// Generate a recipient keypair.
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := []byte("hello sealed box")
	sealed, err := sealedBoxEncrypt(pk, message)
	if err != nil {
		t.Fatalf("sealedBoxEncrypt() error: %v", err)
	}

	// Sealed box should be 32 (epk) + 16 (mac) + len(message).
	expectedLen := 32 + box.Overhead + len(message)
	if len(sealed) != expectedLen {
		t.Errorf("sealed length = %d, want %d", len(sealed), expectedLen)
	}

	// Decrypt.
	plaintext, err := sealedBoxDecrypt(pk, sk, sealed)
	if err != nil {
		t.Fatalf("sealedBoxDecrypt() error: %v", err)
	}
	if string(plaintext) != string(message) {
		t.Errorf("plaintext = %q, want %q", plaintext, message)
	}
}

func TestSealedBoxEncrypt_EmptyMessage(t *testing.T) {
	pk, sk, _ := box.GenerateKey(rand.Reader)

	sealed, err := sealedBoxEncrypt(pk, []byte{})
	if err != nil {
		t.Fatalf("sealedBoxEncrypt(empty) error: %v", err)
	}

	plaintext, err := sealedBoxDecrypt(pk, sk, sealed)
	if err != nil {
		t.Fatalf("sealedBoxDecrypt(empty) error: %v", err)
	}
	if len(plaintext) != 0 {
		t.Errorf("plaintext length = %d, want 0", len(plaintext))
	}
}

func TestEncryptProvingRequest_InvalidHex(t *testing.T) {
	_, err := encryptProvingRequest("not-hex", []byte("test"))
	if err == nil {
		t.Error("encryptProvingRequest(bad hex) should return error")
	}
}

func TestEncryptProvingRequest_WrongKeyLength(t *testing.T) {
	_, err := encryptProvingRequest("aabb", []byte("test"))
	if err == nil {
		t.Error("encryptProvingRequest(short key) should return error")
	}
}

// ─── ProvableClient tests (httptest) ─────────────────────────────────────────

func newTestProvableServer(handler http.HandlerFunc) (*httptest.Server, *ProvableClient) {
	srv := httptest.NewServer(handler)
	client, _ := NewProvableClient(ProvableConfig{
		APIKey:     "test-key",
		ConsumerID: "test-consumer",
		ProverURL:  srv.URL,
		HTTPClient: srv.Client(),
	})
	return srv, client
}

func TestProvableClient_SubmitProvingRequest_Unencrypted(t *testing.T) {
	srv, client := newTestProvableServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwts/test-consumer":
			w.Header().Set("Authorization", "Bearer test-jwt")
			w.WriteHeader(http.StatusOK)
		case "/prove":
			if r.Header.Get("Authorization") != "Bearer test-jwt" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"transaction":{"id":"at1txid123"},"broadcast_result":{"status":"Skipped"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	// Override JWT URL to point at test server.
	client.consumerID = "test-consumer"

	pr := &ProvingRequest{
		Authorization: json.RawMessage(`{"requests":[],"transitions":[]}`),
		Broadcast:     false,
	}

	result, err := client.SubmitProvingRequestSafe(context.Background(), DelegatedProvingParams{
		ProvingRequest: pr,
	})
	if err != nil {
		t.Fatalf("SubmitProvingRequestSafe() error: %v", err)
	}
	if !result.OK {
		t.Fatalf("result.OK = false, error: %v", result.Error)
	}

	txID, err := result.Data.TransactionID()
	if err != nil {
		t.Fatalf("TransactionID() error: %v", err)
	}
	if txID != "at1txid123" {
		t.Errorf("txID = %q, want 'at1txid123'", txID)
	}
}

func TestProvableClient_SubmitProvingRequest_HTTP400(t *testing.T) {
	srv, client := newTestProvableServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwts/test-consumer":
			w.Header().Set("Authorization", "Bearer test-jwt")
			w.WriteHeader(http.StatusOK)
		case "/prove":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"invalid input"}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	pr := &ProvingRequest{
		Authorization: json.RawMessage(`{}`),
	}

	result, err := client.SubmitProvingRequestSafe(context.Background(), DelegatedProvingParams{
		ProvingRequest: pr,
	})
	if err != nil {
		t.Fatalf("SubmitProvingRequestSafe() error: %v", err)
	}
	if result.OK {
		t.Fatal("result.OK = true, want false for 400")
	}
	if result.Status != 400 {
		t.Errorf("result.Status = %d, want 400", result.Status)
	}
	if result.Error.Message != "invalid input" {
		t.Errorf("error message = %q, want 'invalid input'", result.Error.Message)
	}
}

func TestProvableClient_SubmitProvingRequest_RetryOn500(t *testing.T) {
	attempts := 0
	srv, client := newTestProvableServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwts/test-consumer":
			w.Header().Set("Authorization", "Bearer test-jwt")
			w.WriteHeader(http.StatusOK)
		case "/prove":
			attempts++
			if attempts <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"internal error"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"transaction":{"id":"at1retry"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	pr := &ProvingRequest{
		Authorization: json.RawMessage(`{}`),
	}

	resp, err := client.SubmitProvingRequest(context.Background(), DelegatedProvingParams{
		ProvingRequest: pr,
	})
	if err != nil {
		t.Fatalf("SubmitProvingRequest() error after retries: %v", err)
	}

	txID, err := resp.TransactionID()
	if err != nil {
		t.Fatalf("TransactionID() error: %v", err)
	}
	if txID != "at1retry" {
		t.Errorf("txID = %q, want 'at1retry'", txID)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestProvableClient_JWTCaching(t *testing.T) {
	jwtCalls := 0
	srv, client := newTestProvableServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwts/test-consumer":
			jwtCalls++
			w.Header().Set("Authorization", fmt.Sprintf("Bearer jwt-%d", jwtCalls))
			w.WriteHeader(http.StatusOK)
		case "/prove":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"transaction":{"id":"at1cached"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	pr := &ProvingRequest{Authorization: json.RawMessage(`{}`)}

	// First request: should fetch JWT.
	_, err := client.SubmitProvingRequest(context.Background(), DelegatedProvingParams{ProvingRequest: pr})
	if err != nil {
		t.Fatalf("first request error: %v", err)
	}
	if jwtCalls != 1 {
		t.Errorf("jwt calls after first request = %d, want 1", jwtCalls)
	}

	// Second request: should use cached JWT.
	_, err = client.SubmitProvingRequest(context.Background(), DelegatedProvingParams{ProvingRequest: pr})
	if err != nil {
		t.Fatalf("second request error: %v", err)
	}
	if jwtCalls != 1 {
		t.Errorf("jwt calls after second request = %d, want 1 (cached)", jwtCalls)
	}
}

func TestProvableClient_GetPublicKey(t *testing.T) {
	srv, client := newTestProvableServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pubkey":
			if r.Header.Get("Authorization") != "Bearer test-jwt" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key_id":"key123","public_key":"aabbccdd"}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	pubkey, err := client.GetPublicKey(context.Background(), "Bearer test-jwt")
	if err != nil {
		t.Fatalf("GetPublicKey() error: %v", err)
	}
	if pubkey.KeyID != "key123" {
		t.Errorf("KeyID = %q, want 'key123'", pubkey.KeyID)
	}
	if pubkey.PublicKey != "aabbccdd" {
		t.Errorf("PublicKey = %q, want 'aabbccdd'", pubkey.PublicKey)
	}
}

func TestHandleProvingResponse_Success(t *testing.T) {
	body := []byte(`{"transaction":{"id":"at1test"},"broadcast_result":{"status":"Accepted","status_code":200}}`)
	result := handleProvingResponse(200, body)
	if !result.OK {
		t.Fatal("expected OK")
	}
	txID, err := result.Data.TransactionID()
	if err != nil {
		t.Fatalf("TransactionID() error: %v", err)
	}
	if txID != "at1test" {
		t.Errorf("txID = %q, want 'at1test'", txID)
	}
}

func TestHandleProvingResponse_Error(t *testing.T) {
	body := []byte(`{"message":"bad request"}`)
	result := handleProvingResponse(400, body)
	if result.OK {
		t.Fatal("expected not OK")
	}
	if result.Status != 400 {
		t.Errorf("status = %d, want 400", result.Status)
	}
	if result.Error.Message != "bad request" {
		t.Errorf("message = %q, want 'bad request'", result.Error.Message)
	}
}
