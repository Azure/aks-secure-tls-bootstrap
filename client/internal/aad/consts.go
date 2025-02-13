// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package aad

import "time"

const (
	// Max delay for retrying requests to AAD.
	maxGetTokenDelay = 10 * time.Second
	// Max number of retries for requests to AAD.
	maxGetTokenRetries = 10
)
