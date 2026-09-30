//go:build !windows

package msauth

// acquireWAM is never selected off Windows. The placeholder keeps the shared
// command boundary buildable for callers that use Azure CLI-only policy.
const wamScript = ""
