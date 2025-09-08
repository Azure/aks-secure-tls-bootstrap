// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package telemetry provides a simple functionality to measure the duration of individual tasks, or "spans".
// This allows us to track, for every top-level bootstrapping step/operation, how long it took to complete.
// While inspired by OTel distributed tracing concepts, all tracing functionality provided by this package is strictly local.
// The primary goal of the functionality provided in this package is to augment guest agent event telemetry with tracing data.
package telemetry

import (
	"context"
	"time"
)

// span represents a unit of work measured by a start and end time.
type span struct {
	start, end time.Time
}

// spanEnder is a function which ends a particular span on a Tracer.
type spanEnder func()

// tracerContextKey is used to store tracers on context objects.
type tracerContextKey struct{}

type tracer struct {
	spans map[string]*span
}

func newTracer() *tracer {
	return &tracer{
		spans: make(map[string]*span),
	}
}

func (r *tracer) startSpan(spanName string) {
	r.spans[spanName] = &span{
		start: time.Now(),
	}
}

func (r *tracer) endSpan(spanName string) {
	endTime := time.Now()
	if _, ok := r.spans[spanName]; !ok {
		return
	}
	r.spans[spanName].end = endTime
}

// GetTrace returns the duration of all spans recorded since the tracer was originally created,
// OR the last time GetTrace was called. After calling this method, all span data is cleared.
func (r *tracer) getTrace() Trace {
	trace := make(Trace, len(r.spans))
	for spanName, span := range r.spans {
		trace[spanName] = span.end.Sub(span.start)
	}
	r.spans = make(map[string]*span)
	return trace
}

// WithTracing returns a child context with tracing capabilities.
func WithTracing(ctx context.Context) context.Context {
	return context.WithValue(ctx, tracerContextKey{}, newTracer())
}

// StartSpan starts a span with the given name. This function panics if the context
// or any of its parents wasn't created by WithTracing.
func StartSpan(ctx context.Context, spanName string) spanEnder {
	tracer := mustGetTracer(ctx)
	tracer.startSpan(spanName)
	return func() {
		tracer.endSpan(spanName)
	}
}

// GetTrace returns the currently-stored trace on the context. This function panics if
// the context or any of its parents wasn't created by WithTracing.
func GetTrace(ctx context.Context) Trace {
	return mustGetTracer(ctx).getTrace()
}

func mustGetTracer(ctx context.Context) *tracer {
	tracer, ok := ctx.Value(tracerContextKey{}).(*tracer)
	if !ok {
		panic("Tracer is missing from context")
	}
	return tracer
}
