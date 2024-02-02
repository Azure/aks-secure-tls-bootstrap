// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package util

import (
	"encoding/json"
	"fmt"
)

// +gocover:ignore:already tested by other pkgs
func LoadJSONFromPath(fs FS, path string, out interface{}) error {
	jsonBytes, err := fs.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if err = json.Unmarshal(jsonBytes, out); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}
	return nil
}
