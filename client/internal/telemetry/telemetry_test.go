// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTracer(t *testing.T) {
	tracer := newTracer()
	assert.NotNil(t, tracer)

	spanName := "TestSpan"
	tracer.startSpan(spanName)
	span, ok := tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.Zero(t, span.end)
	tracer.startSpan(spanName)
	span, ok = tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.Zero(t, span.end)

	tracer.endSpan(spanName)
	span, ok = tracer.spans[spanName]
	assert.True(t, ok)
	assert.NotNil(t, span)
	assert.NotZero(t, span.start)
	assert.NotZero(t, span.end)

	tracer.endSpan("non-existent-span")
	assert.Len(t, tracer.spans, 1)

	trace := tracer.getTrace()
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
	assert.Equal(t, traceString, fmt.Sprintf(`{"TestSpanMilliseconds":%d}`, duration.Milliseconds()))
}

func TestStartStopSpan(t *testing.T) {
	ctx := WithTracing(context.Background())
	assert.NotNil(t, ctx)

	spanName := "TestSpan"
	endSpan := StartSpan(ctx, spanName)
	assert.NotNil(t, endSpan)

	endSpan()

	trace := GetTrace(ctx)
	assert.NotNil(t, trace)

	spanDuration, ok := trace[spanName]
	assert.True(t, ok)
	assert.NotZero(t, spanDuration)

	assert.Empty(t, GetTrace(ctx))
}

func TestWithTracing(t *testing.T) {
	ctx := WithTracing(context.Background())
	assert.NotNil(t, ctx)

	tracer := mustGetTracer(ctx)
	assert.NotNil(t, tracer)
}

func TestMustGetTracer(t *testing.T) {
	ctx := WithTracing(context.Background())
	tracer := mustGetTracer(ctx)
	assert.NotNil(t, tracer)

	ctx = context.Background()
	assert.Panics(t, func() {
		mustGetTracer(ctx)
	})
}
