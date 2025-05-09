package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	performSecureTLSBootstrappingGuestAgentEventName = "AKS.performSecureTLSBootstrapping"
)

var (
	guestAgentEventsPathLinux   string
	guestAgentEventsPathWindows string
)

var isWindows func() bool

func init() {
	guestAgentEventsPathLinux = "/var/log/azure/Microsoft.Azure.Extensions.CustomScript/events"
	guestAgentEventsPathWindows = "C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.Compute.CustomScriptExtension\\Events"

	isWindows = func() bool {
		return runtime.GOOS == "windows"
	}
}

func getGuestAgentEventsPath() string {
	if isWindows() {
		return guestAgentEventsPathWindows
	}
	return guestAgentEventsPathLinux
}

type Status string

const (
	StatusSuccess Status = "Success"
	StatusFailure Status = "Failure"
)

type Result struct {
	Status         Status            `json:"Status"`
	ElapsedSeconds float64           `json:"ElapsedSeconds,omitempty"`
	ErrorFreqs     map[ErrorType]int `json:"BootstrapErrorFrequencies,omitempty"`
	Error          string            `json:"Error,omitempty"`
}

type Event struct {
	Message string
	Start   time.Time
	End     time.Time
}

var _ json.Marshaler = (*Event)(nil)

// Event instances are marshaled according to the GuestAgentGenericLogsSchema object used
// by the azure guest agent (WALinuxAgent).
// For details, see: https://github.com/Azure/WALinuxAgent/blob/master/azurelinuxagent/common/telemetryevent.py#L49
func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TaskName    string `json:"TaskName"`
		OperationID string `json:"OperationId"`
		Timestamp   string `json:"Timestamp"`
		Version     string `json:"Version"`
		EventLevel  string `json:"EventLevel"`
		Message     string `json:"Message"`
		EventPID    string `json:"EventPid"`
		EventTID    string `json:"EventTid"`
	}{
		TaskName:    performSecureTLSBootstrappingGuestAgentEventName,
		Timestamp:   e.Start.Format("2006-01-02 15:04:05.000"),
		OperationID: e.End.Format("2006-01-02 15:04:05.000"),
		Message:     e.Message,
		Version:     "1.23",
		EventLevel:  "Informational",
		EventPID:    "0",
		EventTID:    "0",
	})
}

func (e *Event) WriteWithResult(result *Result) (string, error) {
	resultBytes, err := json.Marshal(result)
	if err != nil {
		e.Message = "Completed"
	} else {
		e.Message = string(resultBytes)
	}
	return e.write()
}

func (e *Event) write() (string, error) {
	path := filepath.Join(getGuestAgentEventsPath(), fmt.Sprintf("%d.json", e.Start.UnixNano()))
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, eventBytes, os.ModePerm); err != nil {
		return "", err
	}
	return path, nil
}
