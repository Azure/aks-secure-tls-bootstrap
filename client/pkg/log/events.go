package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.uber.org/zap"
)

const (
	linuxEventsDir   = "/var/log/azure/Microsoft.Azure.Extensions.CustomScript/events/"
	windowsEventsDir = "C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.Compute.CustomScriptExtension\\Events\\"
)

var eventsDir string

func init() {
	eventsDir = linuxEventsDir
	if isWindows() {
		eventsDir = windowsEventsDir
	}
}

type timerFunc func() time.Duration

// CustomScriptEvent contains the fields that custom script event requires. Instances of this
// struct will be marshaled and written to disk such that either the Azure Linux/Windows
// VM agent can pick it up and ship it off to Kusto.
// See this: https://github.com/Azure/AgentBaker/blob/master/parts/linux/cloud-init/artifacts/cse_helpers.sh#L337-L367 for an example.
type customScriptEvent struct {
	Timestamp   string `json:"Timestamp"`   // start time
	OperationID string `json:"OperationId"` // end time
	Version     string `json:"Version"`
	TaskName    string `json:"TaskName"` // task name
	EventLevel  string `json:"EventLevel"`
	Message     string `json:"Message"`
	EventPID    string `json:"EventPid"`
	EventTID    string `json:"EventTid"`
}

func (e *customScriptEvent) deliver() error {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event %s for writing: %w", e.TaskName, err)
	}
	if err = os.WriteFile(filepath.Join(eventsDir, e.Timestamp), eventBytes, os.ModePerm); err != nil {
		return fmt.Errorf("write event content for %s to disk: %w", e.TaskName, err)
	}
	return nil
}

type Event[T any] struct {
	Action    func() (T, error)
	Name      string
	OnFailure string
	Logger    *zap.Logger
}

func (e *Event[T]) Perform() (res T, err error) {
	// run and time the action
	startTime, timer := startTimer()
	res, err = e.Action()
	ellapsed := timer()

	var msg string
	if err == nil {
		msg = fmt.Sprintf("Completed %s", e.Name)
	} else {
		msg = fmt.Sprintf("Failed to perform %s : %s", e.Name, e.OnFailure)
	}

	// create the corresponding custom script event
	cseEvent := &customScriptEvent{
		Timestamp:   startTime.String(),
		OperationID: ellapsed.String(),
		TaskName:    e.Name,
		Message:     msg,
	}

	if err = cseEvent.deliver(); err != nil {
		e.Logger.Error("event delivery", zap.Error(err))
	}

	return res, err
}

func startTimer() (time.Time, timerFunc) {
	start := time.Now()
	return start, func() time.Duration {
		return time.Since(start)
	}
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}
