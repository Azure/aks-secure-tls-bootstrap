package events

import (
	"time"

	"go.uber.org/zap"
)

type Config struct {
	TargetDir string
	Logger    *zap.Logger
}

type Event[T any] struct {
	Action func() (T, error)
	Name   string
}

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

type timerFunc func() time.Duration
