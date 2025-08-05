package telemetry

import (
	"encoding/json"
	"time"
)

type tracerContextKey struct{}

type span struct {
	start, end time.Time
}

// Trace is a mapping of span names to their corresponding durations as measured by a Tracer.
type Trace map[string]time.Duration

var _ json.Marshaler = (Trace)(nil)

// MarshalJSON implements the json.Marshaler interface for Trace.
// All span durations are converted to milliseconds.
func (t Trace) MarshalJSON() ([]byte, error) {
	res := make(map[string]int64, len(t))
	for spanName, spanDuration := range t {
		name := spanName + "Milliseconds"
		res[name] = spanDuration.Milliseconds()
	}
	return json.Marshal(res)
}
