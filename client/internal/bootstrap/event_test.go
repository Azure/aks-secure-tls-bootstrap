package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLinuxEvent(t *testing.T) {
	guestAgentEventsPathLinux = t.TempDir()
	guestAgentEventsPathWindows = t.TempDir()
	isWindows = func() bool {
		return false
	}

	now := time.Now()
	e := &Event{
		Start:   now,
		End:     now.Add(time.Minute),
		Message: "linux",
		Level:   "Informational",
	}

	path, err := e.write()
	assert.NoError(t, err)
	assert.True(t, strings.HasSuffix(path, fmt.Sprintf("%d.json", now.UnixNano())))

	windowsEntries, err := os.ReadDir(guestAgentEventsPathWindows)
	assert.NoError(t, err)
	assert.Empty(t, windowsEntries)

	entries, err := os.ReadDir(guestAgentEventsPathLinux)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	eventEntry := entries[0]
	assert.Equal(t, fmt.Sprintf("%d.json", now.UnixNano()), eventEntry.Name())

	content, err := os.ReadFile(filepath.Join(guestAgentEventsPathLinux, eventEntry.Name()))
	assert.NoError(t, err)

	eventData := map[string]interface{}{}
	err = json.Unmarshal(content, &eventData)
	assert.NoError(t, err)

	assert.Equal(t, performSecureTLSBootstrappingGuestAgentEventName, eventData["TaskName"])
	assert.Equal(t, "Informational", eventData["EventLevel"])
	assert.Equal(t, now.Format("2006-01-02 15:04:05.000"), eventData["Timestamp"])
	assert.Equal(t, now.Add(time.Minute).Format("2006-01-02 15:04:05.000"), eventData["OperationId"])
	assert.Equal(t, "linux", eventData["Message"])
	assert.Equal(t, "1.23", eventData["Version"])
	assert.Equal(t, "0", eventData["EventPid"])
	assert.Equal(t, "0", eventData["EventTid"])
}

func TestWindowsEvent(t *testing.T) {
	guestAgentEventsPathLinux = t.TempDir()
	guestAgentEventsPathWindows = t.TempDir()
	isWindows = func() bool {
		return true
	}

	now := time.Now()
	e := &Event{
		Start:   now,
		End:     now.Add(time.Minute),
		Message: "windows",
		Level:   "Informational",
	}

	path, err := e.write()
	assert.NoError(t, err)
	assert.True(t, strings.HasSuffix(path, fmt.Sprintf("%d.json", now.UnixNano())))

	linuxEntries, err := os.ReadDir(guestAgentEventsPathLinux)
	assert.NoError(t, err)
	assert.Empty(t, linuxEntries)

	windowsEntries, err := os.ReadDir(guestAgentEventsPathWindows)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(windowsEntries))
	eventEntry := windowsEntries[0]
	assert.Equal(t, fmt.Sprintf("%d.json", now.UnixNano()), eventEntry.Name())

	content, err := os.ReadFile(filepath.Join(guestAgentEventsPathWindows, eventEntry.Name()))
	assert.NoError(t, err)

	eventData := map[string]interface{}{}
	err = json.Unmarshal(content, &eventData)
	assert.NoError(t, err)

	assert.Equal(t, performSecureTLSBootstrappingGuestAgentEventName, eventData["TaskName"])
	assert.Equal(t, "Informational", eventData["EventLevel"])
	assert.Equal(t, now.Format("2006-01-02 15:04:05.000"), eventData["Timestamp"])
	assert.Equal(t, now.Add(time.Minute).Format("2006-01-02 15:04:05.000"), eventData["OperationId"])
	assert.Equal(t, "windows", eventData["Message"])
	assert.Equal(t, "1.10", eventData["Version"])
	assert.Equal(t, "0", eventData["EventPid"])
	assert.Equal(t, "0", eventData["EventTid"])
}
