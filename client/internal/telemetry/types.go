package telemetry

import (
	"encoding/json"
	"time"
)

type tracerContextKey struct{}

type span struct {
	start, end time.Time
}

type Trace map[string]time.Duration

var _ json.Marshaler = (Trace)(nil)

// MarshalJSON implements the json.Marshaler interface for Trace.
// All span durations are converted to milliseconds.
func (t Trace) MarshalJSON() ([]byte, error) {
	result := make(map[string]int64, len(t))
	for spanName, spanDuration := range t {
		result[spanName] = spanDuration.Milliseconds()
	}
	return json.Marshal(result)
}
