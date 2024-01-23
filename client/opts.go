// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

import "fmt"

type SecureTLSBootstrapClientOpts struct {
	CustomClientID            string
	NextProto                 string
	AADResource               string
	LogFormat                 string
	KubeconfigPath            string
	Verbose                   bool
	EnsureClusterConnectivity bool
}

func (o SecureTLSBootstrapClientOpts) Validate() error {
	if o.NextProto == "" {
		return fmt.Errorf("next-proto must be specified to generate bootstrap tokens")
	}
	if o.AADResource == "" {
		return fmt.Errorf("aad-resource must be specified to generate bootstrap tokens")
	}
	return nil
}
