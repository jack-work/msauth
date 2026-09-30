//go:build !windows

package msauth

import "context"

// The Windows broker exists only on Windows. The stubs keep the shared
// selection logic and its tests buildable everywhere, and give a caller the
// same deterministic code it would get from a Windows machine with no broker.

func resolveBroker(context.Context) (*brokerSelection, *AuthError) {
	return nil, &AuthError{Code: CodeWAMUnavailable, Message: "WAM is available only on Windows"}
}

// ProbeBrokerHost reports that no broker inventory exists off Windows.
func ProbeBrokerHost(context.Context, string) (BrokerInventory, error) {
	return BrokerInventory{}, &AuthError{Code: CodeWAMUnavailable, Message: "WAM is available only on Windows"}
}
