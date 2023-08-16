// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import "runtime"

func isWindows() bool {
	return runtime.GOOS == "windows"
}
