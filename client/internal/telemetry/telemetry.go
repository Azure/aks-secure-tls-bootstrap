package telemetry

import (
	"context"
	"time"
)

type Tracer interface {
	StartSpan(spanName string)
	EndSpan(spanName string)
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

// GetTrace returns the duration of all spans recorded since the tracer was originally created,
// OR the last time GetTrace was called. After calling this method, all span data is cleared.
func (r *tracer) GetTrace() Trace {
	trace := make(Trace, len(r.spans))
	for spanName, span := range r.spans {
		trace[spanName] = span.end.Sub(span.start)
	}
	r.spans = make(map[string]*span)
	return trace
}

func NewContext() context.Context {
	return context.WithValue(context.Background(), tracerContextKey{}, NewTracer())
}

func WithTracer(ctx context.Context, tracer Tracer) context.Context {
	return context.WithValue(ctx, tracerContextKey{}, tracer)
}

func MustGetTracer(ctx context.Context) Tracer {
	tracer, ok := ctx.Value(tracerContextKey{}).(Tracer)
	if !ok {
		panic("Tracer is missing from context")
	}
	return tracer
}
