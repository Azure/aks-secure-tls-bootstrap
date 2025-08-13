// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

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

func TestTraceStore(t *testing.T) {
	store := NewTraceStore()
	assert.NotNil(t, store)
	assert.NotNil(t, store.traces)
	assert.Empty(t, store.traces)

	trace0 := Trace{"span": 100 * time.Millisecond}
	trace1 := Trace{"span": 200 * time.Millisecond}
	trace2 := Trace{"span": 300 * time.Millisecond}

	store.Add(trace0)
	store.Add(trace1)
	store.Add(trace2)

	traces := store.GetLastNTraces(3)
	assert.Len(t, traces, 3)
	assert.Equal(t, trace0, traces[0])
	assert.Equal(t, trace1, traces[1])
	assert.Equal(t, trace2, traces[2])

	summary := store.GetTraceSummary()
	assert.Len(t, summary, 1)
	assert.Equal(t, 600*time.Millisecond, summary["span"])

	store = NewTraceStore()

	trace0 = Trace{"span": 100 * time.Millisecond}
	trace1 = Trace{"span": 200 * time.Millisecond}
	trace2 = Trace{"span": 300 * time.Millisecond}
	trace3 := Trace{"span": 400 * time.Millisecond}

	store.Add(trace0)
	store.Add(trace1)
	store.Add(trace2)
	store.Add(trace3)

	traces = store.GetLastNTraces(3)
	assert.Len(t, traces, 3)
	assert.Contains(t, traces, 1)
	assert.Contains(t, traces, 2)
	assert.Contains(t, traces, 3)

	assert.Equal(t, trace1, traces[1])
	assert.Equal(t, trace2, traces[2])
	assert.Equal(t, trace3, traces[3])

	summary = store.GetTraceSummary()
	assert.Len(t, summary, 1)
	assert.Equal(t, time.Second, summary["span"])

	store = NewTraceStore()
	store.Add(trace0)

	traces = store.GetLastNTraces(3)
	assert.Len(t, traces, 1)
	assert.Equal(t, trace0, traces[0])

	summary = store.GetTraceSummary()
	assert.Len(t, summary, 1)
	assert.Equal(t, 100*time.Millisecond, summary["span"])
}
