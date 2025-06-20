package telemetry

import (
	"context"
	"time"
)

type TaskRecorder interface {
	Start(eventName string)
	Stop(eventName string)
	GetRecording() Recording
}

type taskRecorder struct {
	events map[string]event
}

var _ TaskRecorder = (*taskRecorder)(nil)

func NewTaskRecorder() TaskRecorder {
	return &taskRecorder{
		events: make(map[string]event),
	}
}

func (r *taskRecorder) Start(eventName string) {
	r.events[eventName] = event{
		name:  eventName,
		start: time.Now(),
	}
}

func (r *taskRecorder) Stop(eventName string) {
	if _, ok := r.events[eventName]; !ok {
		return
	}
	e := r.events[eventName]
	e.end = time.Now()
	r.events[eventName] = e
}

func (r *taskRecorder) GetRecording() Recording {
	recording := make(Recording, len(r.events))
	for name, event := range r.events {
		recording[name] = event.end.Sub(event.start)
	}
	r.events = make(map[string]event)
	return recording
}

func NewContext() context.Context {
	return context.WithValue(context.Background(), taskRecorderContextKey{}, NewTaskRecorder())
}

func WithTaskRecorder(ctx context.Context, recorder TaskRecorder) context.Context {
	return context.WithValue(ctx, taskRecorderContextKey{}, recorder)
}

func MustGetTaskRecorder(ctx context.Context) TaskRecorder {
	recorder, ok := ctx.Value(taskRecorderContextKey{}).(TaskRecorder)
	if !ok {
		panic("TaskRecorder is missing from context")
	}
	return recorder
}
