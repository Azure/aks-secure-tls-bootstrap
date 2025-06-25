package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTracer(t *testing.T) {
	newTracer := NewTracer()
	assert.NotNil(t, newTracer)

	tracer, ok := (newTracer).(*tracer)
	assert.True(t, ok)

	spanName := "test-span"
	tracer.StartSpan(spanName)
	span, ok := tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.Zero(t, span.end)
	tracer.StartSpan(spanName)
	span, ok = tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.Zero(t, span.end)

	tracer.EndSpan(spanName)
	span, ok = tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.NotZero(t, span.end)

	tracer.EndSpan("non-existent-span")
	assert.Len(t, tracer.spans, 1)

	trace := tracer.GetTrace()
	assert.NotNil(t, trace)
	assert.Empty(t, tracer.spans)
	assert.Len(t, trace, 1)
	duration, ok := trace[spanName]
	assert.True(t, ok)
	assert.NotZero(t, duration)

	traceBytes, err := json.Marshal(trace)
	assert.NoError(t, err)

	traceString := string(traceBytes)
	assert.Contains(t, traceString, spanName)
	assert.Equal(t, traceString, fmt.Sprintf(`{"test-span":%d}`, duration.Milliseconds()))
}

func TestNewContext(t *testing.T) {
	ctx := NewContext()
	assert.NotNil(t, ctx)

	tracer := MustGetTracer(ctx)
	assert.NotNil(t, tracer)
}

func TestWithTracer(t *testing.T) {
	ctx := context.Background()
	tracer := NewTracer()
	assert.NotNil(t, tracer)

	ctx = WithTracer(ctx, tracer)
	assert.NotNil(t, ctx)

	tracer = MustGetTracer(ctx)
	assert.NotNil(t, tracer)
}

func TestMustGetTracer(t *testing.T) {
	ctx := NewContext()
	tracer := MustGetTracer(ctx)
	assert.NotNil(t, tracer)

	ctx = context.Background()
	assert.Panics(t, func() {
		MustGetTracer(ctx)
	})
}
