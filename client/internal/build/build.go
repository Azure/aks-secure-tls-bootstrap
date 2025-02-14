package build

import "fmt"

// Version holds the client binary's current version string.
var Version string

// GetUserAgentValue returns the common User-Agent header value used in all RPCs and HTTP calls.
func GetUserAgentValue() string {
	return fmt.Sprintf("aks-secure-tls-bootstrap-client/%s", Version)
}
