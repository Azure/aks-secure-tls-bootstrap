// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tls-bootstrap-client",
	Short: "tls-bootstrap-client - secure TLS bootstrap client used to generated dynamic TLS bootstrap tokens via the AKS secure TLS bootstrapping protocol",
}
