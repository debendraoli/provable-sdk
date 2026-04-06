//go:build goexperiment.runtimesecret

package sdk

import "runtime/secret"

// zeroizeAccount uses runtime/secret.Erase for secure key erasure.
// This is gated behind the runtimesecret GOEXPERIMENT build tag.
// When the experiment is not enabled, the default manual loop in account.go is used.
func zeroizeAccount(a *Account) {
	secret.Erase(a.privateKey)
	secret.Erase(a.viewKey)
	secret.Erase(a.computeKey)
	secret.Erase(a.graphKey)
	a.privateKey = nil
	a.viewKey = nil
	a.computeKey = nil
	a.graphKey = nil
	a.address = ""
}
