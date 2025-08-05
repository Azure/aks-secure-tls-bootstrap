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
