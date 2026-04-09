package bootstrap

import (
	"context"
	"runtime"

	"k8s.io/client-go/tools/clientcmd/api"
)

var (
	// this is the designated path on Linux VMs running on Azure where the guest agent will watch for
	// and collect event telemetry payloads - overridden in unit tests
	guestAgentEventsPathLinux string

	// this is the designated path on Windows VMs running on Azure where the guest agent will watch for
	// and collect event telemetry payloads - overridden in unit tests
	guestAgentEventsPathWindows string
)

// this function simply determines whether the operating system is Windows - overridden in unit tests
var isWindows func() bool

// this function is used to perform the bootstrapping process - overridden in unit tests
var bootstrapFunc func(ctx context.Context, config *Config) (*api.Config, error)

func init() {
	guestAgentEventsPathLinux = "/var/log/azure/Microsoft.Azure.Extensions.CustomScript/events"
	guestAgentEventsPathWindows = "C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.Compute.CustomScriptExtension\\Events"

	isWindows = func() bool {
		return runtime.GOOS == "windows"
	}

	bootstrapFunc = func(ctx context.Context, config *Config) (*api.Config, error) {
		return newClient(ctx).bootstrap(ctx, config)
	}
}
