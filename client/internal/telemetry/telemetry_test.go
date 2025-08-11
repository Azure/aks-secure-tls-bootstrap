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
	newTracer := NewTracer()
	assert.NotNil(t, newTracer)

	tracer, ok := (newTracer).(*tracer)
	assert.True(t, ok)

	spanName := "TestSpan"
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
	assert.Equal(t, traceString, fmt.Sprintf(`{"TestSpanMilliseconds":%d}`, duration.Milliseconds()))
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
