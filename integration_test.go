//go:build integration

package sdk

import (
	"context"
	"testing"
)

func TestIntegration_AccountRoundTrip(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}
	msg := []byte("integration test message")
	sig, err := account.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	ok, err := Verify(account.Address(), msg, sig)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Fatal("Verify() = false for valid signature")
	}
	reimported, err := AccountFromPrivateKey(account.PrivateKey())
	if err != nil {
		t.Fatalf("AccountFromPrivateKey() error: %v", err)
	}
	ok, err = Verify(reimported.Address(), msg, sig)
	if err != nil {
		t.Fatalf("Verify(reimported) error: %v", err)
	}
	if !ok {
		t.Fatal("Verify(reimported) = false")
	}
}

func TestIntegration_TestnetBlockHeight(t *testing.T) {
	client := NewClient("https://api.explorer.provable.com/v2", TestnetV0)
	height, err := client.GetLatestBlockHeight(context.Background())
	if err != nil {
		t.Fatalf("GetLatestBlockHeight() error: %v", err)
	}
	if height == 0 {
		t.Error("GetLatestBlockHeight() = 0, expected > 0")
	}
	t.Logf("Testnet height: %d", height)
}

func TestIntegration_GetCreditsProgram(t *testing.T) {
	client := NewClient("https://api.explorer.provable.com/v2", TestnetV0)
	src, err := client.GetProgram(context.Background(), "credits.aleo")
	if err != nil {
		t.Fatalf("GetProgram() error: %v", err)
	}
	if src == "" {
		t.Error("GetProgram() returned empty source")
	}
	t.Logf("credits.aleo source length: %d bytes", len(src))
}

func TestIntegration_BuildAuthorization_Credits(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount() error: %v", err)
	}

	nc := NewNetworkClient("https://api.explorer.provable.com/v2", MainnetV0)
	auth, err := BuildAuthorization(context.Background(), nc, ProvingRequestOptions{
		ProgramName:  "credits.aleo",
		FunctionName: "transfer_public",
		Inputs:       []string{account.Address(), "1000u64"},
		PrivateKey:   account.PrivateKey(),
	})
	if err != nil {
		t.Fatalf("BuildAuthorization() error: %v", err)
	}
	if auth == nil || len(auth.Raw) == 0 {
		t.Fatal("BuildAuthorization() returned nil/empty authorization")
	}
	t.Logf("Authorization JSON length: %d bytes", len(auth.Raw))
}
