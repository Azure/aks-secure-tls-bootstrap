// Package telemetry provides a simple functionality to measure the duration of individual tasks, or "spans".
// This allows us to track, for every top-level bootstrapping step/operation, how long it took to complete.
// While inspired by OTel distributed tracing concepts, all tracing functionality provided by this package is strictly local.
// The primary goal of the functionality provided in this package is to augment guest agent event telemetry with tracing data.
package telemetry

import (
	"context"
	"time"
)

// Tracer provides methods to start and stop "spans" for measuring execution times.
type Tracer interface {
	// StartSpan creates and starts a new span with the given name.
	StartSpan(spanName string)
	// EndSpan stops the span with the given name, if it exists.
	EndSpan(spanName string)
	// GetTrace returns the duration of all spans recorded since the tracer was originally created,
	// OR the last time GetTrace was called. After calling this method, all span data is cleared.
	GetTrace() Trace
}

type tracer struct {
	spans map[string]*span
}

var _ Tracer = (*tracer)(nil)

func NewTracer() Tracer {
	return &tracer{
		spans: make(map[string]*span),
	}
}

func (r *tracer) StartSpan(spanName string) {
	r.spans[spanName] = &span{
		start: time.Now(),
	}
}

func (r *tracer) EndSpan(spanName string) {
	endTime := time.Now()
	if _, ok := r.spans[spanName]; !ok {
		return
	}
	r.spans[spanName].end = endTime
}

func (r *tracer) GetTrace() Trace {
	trace := make(Trace, len(r.spans))
	for spanName, span := range r.spans {
		trace[spanName] = span.end.Sub(span.start)
	}
	r.spans = make(map[string]*span)
	return trace
}

// TraceStore is a fixed-capacity store of Trace objects.
type TraceStore struct {
	traces []Trace
}

func NewTraceStore() *TraceStore {
	return &TraceStore{
		traces: make([]Trace, 0),
	}
}

// Add adds the specific trace the store, using the specified ID. IDs must be added sequentially.
// If the store is at capacity, the oldest trace will be evicted.
func (t *TraceStore) Add(trace Trace) {
	t.traces = append(t.traces, trace)
}

// GetLastNTraces returns the last N traces in within the TraceStore.
// If N is >= the number of traces stored, all traces are returned.
func (t *TraceStore) GetLastNTraces(n int) map[int]Trace {
	result := make(map[int]Trace, n)
	for id := max(len(t.traces)-n, 0); id < len(t.traces); id++ {
		result[id] = t.traces[id]
	}
	return result
}

// GetTraceSummary returns a Trace which summarizes the total duration of each span across all stored traces.
func (t *TraceStore) GetTraceSummary() Trace {
	total := make(Trace)
	for _, trace := range t.traces {
		for spanName, duration := range trace {
			total[spanName] += duration
		}
	}
	return total
}

// NewContext returns a new context object, attached with a newly initialized Tracer.
func NewContext() context.Context {
	return context.WithValue(context.Background(), tracerContextKey{}, NewTracer())
}

// WithTracer returns creates a child context off the specified context with a new Tracer attached.
func WithTracer(ctx context.Context, tracer Tracer) context.Context {
	return context.WithValue(ctx, tracerContextKey{}, tracer)
}

// MustGetTracer retrieves the Tracer from the specified context.
// If a Tracer is not found on the context, it panics.
func MustGetTracer(ctx context.Context) Tracer {
	tracer, ok := ctx.Value(tracerContextKey{}).(Tracer)
	if !ok {
		panic("Tracer is missing from context")
	}
	return tracer
}
