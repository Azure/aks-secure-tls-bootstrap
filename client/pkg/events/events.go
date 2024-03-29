package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// const (
// 	linuxEventsDir   = "/var/log/azure/Microsoft.Azure.Extensions.CustomScript/events/"
// 	windowsEventsDir = "C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.Compute.CustomScriptExtension\\Events\\"
// )

func (c *Config) validate() error {
	if c.Logger == nil {
		return fmt.Errorf("event config logger is nil")
	}
	return nil
}

func (e *Event[T]) Perform(cfg *Config) (res T, err error) {
	if e.Action == nil {
		err = fmt.Errorf("event was created with a nil action")
		return
	}
	err = cfg.validate()
	if err != nil {
		return
	}

	// run and time the action
	startTime, timer := startTimer()
	res, err = e.Action()
	ellapsed := timer()

	var (
		msg        string
		eventLevel string
	)
	if err == nil {
		msg = fmt.Sprintf("Completed %s", e.Name)
		eventLevel = "Informational"
	} else {
		msg = fmt.Sprintf("Failed to perform %s: %s", e.Name, err.Error())
		eventLevel = "Error"
	}

	// create the corresponding custom script event
	cseEvent := &customScriptEvent{
		Timestamp:   startTime.String(),
		OperationID: ellapsed.String(),
		TaskName:    e.Name,
		Message:     msg,
		EventLevel:  eventLevel,
	}

	if deliverErr := cseEvent.deliver(cfg.TargetDir); deliverErr != nil {
		cfg.Logger.Error("event delivery", zap.Error(deliverErr))
	}

	return res, err
}

func (e *customScriptEvent) deliver(path string) error {
	if path == "" {
		return nil
	}
	if e.Version == "" {
		e.Version = "aks-stlsbootstrap-client/v0.1.0" // TODO(cameissner): get version of client binary dynamically
	}
	if e.EventPID == "" {
		e.EventPID = "0"
	}
	if e.EventTID == "" {
		e.EventTID = "0"
	}
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event %s for writing: %w", e.TaskName, err)
	}
	if err = os.WriteFile(filepath.Join(path, e.Timestamp), eventBytes, os.ModePerm); err != nil {
		return fmt.Errorf("write event content for %s to disk: %w", e.TaskName, err)
	}
	return nil
}

func startTimer() (time.Time, timerFunc) {
	start := time.Now()
	return start, func() time.Duration {
		return time.Since(start)
	}
}
