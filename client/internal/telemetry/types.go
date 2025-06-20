package telemetry

import "time"

type taskRecorderContextKey struct{}

type event struct {
	name  string
	start time.Time
	end   time.Time
}

type Recording map[string]time.Duration
