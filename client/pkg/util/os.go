// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package util

import "runtime"

// +gocover:ignore:already tested by other pkgs
func IsWindows() bool {
	return runtime.GOOS == "windows"
}
