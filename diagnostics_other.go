//go:build !windows

package msauth

import "context"

// Off Windows there are two different answers, and collapsing them was a lie
// this file used to tell.
//
// On bare Linux and on macOS there is genuinely no broker, and saying so
// plainly is more useful than omitting the section: a caller comparing two
// machines needs to see why one has none.
//
// Inside WSL there IS one -- the Windows host's, reached over interop (see
// wslbroker.go). Reporting "not supported on this OS" there would send an
// operator to debug the Azure CLI on a machine whose brokered path is the one
// that works, which is the opposite of what a diagnostic is for.
func diagnoseBroker(ctx context.Context) BrokerDiagnostics {
	env := defaultWSLEnvironment()
	if !env.runningUnderWSL() {
		return BrokerDiagnostics{
			Supported: false,
			Error:     &AuthError{Code: CodeWAMUnavailable, Message: "WAM is available only on Windows"},
		}
	}

	diagnostics := BrokerDiagnostics{Supported: true, SelectedHost: "wsl-broker"}

	// Resolving the proxy is the whole health question here, and it is cheap:
	// no token is requested, no account is touched, nothing is signed in.
	// Resolution tries PATH and then the fixed wslinfo locations, so reaching
	// an error here means the interop shim is genuinely missing rather than
	// merely unreachable from this process's PATH.
	proxy, authErr := env.msalProxyPath(ctx)
	if authErr != nil {
		diagnostics.Error = authErr
		return diagnostics
	}
	diagnostics.Overrides = map[string]string{"msal-proxy-path": proxy}
	diagnostics.LoadCheck = &BrokerLoadCheck{Attempted: true, OK: true, Directory: proxy}
	return diagnostics
}
