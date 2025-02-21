package event

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	GuestAgentEventsPathLinux   = "/var/log/azure/Microsoft.Azure.Extensions.CustomScript/events"
	GuestAgentEventsPathWindows = "C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.Compute.CustomScriptExtension\\Events"
)

type Event struct {
	Name    string
	Message string
	Start   time.Time
	End     time.Time
}

var _ json.Marshaler = (*Event)(nil)

func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TaskName    string `json:"TaskName"`
		OperationID string `json:"OperationId"`
		Timestamp   string `json:"Timestamp"`
		Version     string `json:"version"`
		EventLevel  string `json:"EventLevel"`
		Message     string `json:"Message"`
		EventPID    string `json:"EventPid"`
		EventTID    string `json:"EventTid"`
	}{
		TaskName:    e.Name,
		Timestamp:   e.Start.String(),
		OperationID: e.End.String(),
		Message:     e.Message,
		Version:     "1.23",
		EventLevel:  "Informational",
		EventPID:    "0",
		EventTID:    "0",
	})
}

func (e *Event) Write() error {
	path := GuestAgentEventsPathLinux
	if runtime.GOOS == "windows" {
		path = GuestAgentEventsPathWindows
	}
	path = filepath.Join(path, fmt.Sprintf("%d.json", time.Now().UnixNano()))
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, os.ModePerm); err != nil {
		return err
	}
	return nil
}

type BootstrapResult struct {
	Status   string `json:"Status,omitempty"`
	Hostname string `json:"Hostname,omitempty"`
	Log      string `json:"Log,omitempty"`
}
