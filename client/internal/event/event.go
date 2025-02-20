package event

import (
	"encoding/json"
	"time"
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
