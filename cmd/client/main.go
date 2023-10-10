// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import "os"

func main() {
	rootCmd.AddCommand(createBootstrapCommand())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
