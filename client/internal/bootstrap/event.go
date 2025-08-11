// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Azure/aks-secure-tls-bootstrap/client/internal/telemetry"
)

const (
	performSecureTLSBootstrappingGuestAgentEventName = "AKS.Bootstrap.SecureTLSBootstrapping"
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

func getEventVersion() string {
	if isWindows() {
		// corresponds to Microsoft.Compute.CustomScriptExtension-1.10
		return "1.10"
	}
	// corresponds to Microsoft.Azure.Extensions.CustomScript-1.23
	return "1.23"
}

type Status string

const (
	StatusSuccess Status = "Success"
	StatusFailure Status = "Failure"
)

type Result struct {
	// Status is terminal status of the bootstrapping event.
	Status Status `json:"Status"`
	// ElapsedMilliseconds measures how long the bootstrapping event took to execute, in milliseconds.
	ElapsedMilliseconds int64 `json:"ElapsedMilliseconds"`
	// Errors is a mapping from top-level bootstrapping error type of the number of times it occurred during the event.
	Errors map[ErrorType]int `json:"Errors,omitempty"`
	// Traces is a mapping from retry attempt to corresponding Trace. A Trace maps span names to their respective durations.
	// This will only ever contain data for the last 3 retries to avoid truncating guest agent event data.
	Traces map[int]telemetry.Trace `json:"Traces,omitempty"`
	// TraceSummary is a special Trace which maps span names to their total durations across all retry attempts.
	TraceSummary telemetry.Trace `json:"TraceSummary,omitempty"`
	// FinalError is the the error returned by the last retry attempt, assuming the overall bootstrapping event failed.
	FinalError string `json:"FinalError,omitempty"`
}

type Event struct {
	Level   string
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
		Version:     getEventVersion(),
		EventLevel:  e.Level,
		EventPID:    "0",
		EventTID:    "0",
	})
}

func (e *Event) WriteWithResult(result *Result) (string, error) {
	e.Level = "Informational"
	if result.Status == StatusFailure {
		e.Level = "Error"
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		e.Message = "Completed"
	} else {
		e.Message = string(resultBytes)
	}
	return e.write()
}

func (e *Event) write() (string, error) {
	guestAgentEventsPath := getGuestAgentEventsPath()
	if _, err := os.Stat(guestAgentEventsPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stating guest agent event path %s: %w", guestAgentEventsPath, err)
	}
	eventFilePath := filepath.Join(guestAgentEventsPath, fmt.Sprintf("%d.json", e.Start.UnixNano()))
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshalling bootstrap event data: %w", err)
	}
	if err := os.WriteFile(eventFilePath, eventBytes, os.ModePerm); err != nil {
		return "", fmt.Errorf("writing bootstrap event data to disk: %w", err)
	}
	return eventFilePath, nil
}
