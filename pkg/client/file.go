// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../../bin/mockgen -copyright_file=../../hack/copyright_header.txt -destination=./mocks/mock_file.go -package=mocks github.com/Azure/aks-tls-bootstrap-client/pkg/client FileReader

import "os"

// fileReader proves methods to interact with the host file system
// needed by the bootstrap server in order to properly perform setup.
// This is primarily used for mockability within unit tests.
type FileReader interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]os.DirEntry, error)
}

type osFileReader struct{}

func NewOSFileReader() FileReader {
	return &osFileReader{}
}

func (r *osFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (r *osFileReader) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
}
