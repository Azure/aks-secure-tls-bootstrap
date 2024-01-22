// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package client

//go:generate ../bin/mockgen -source=file.go -copyright_file=../hack/copyright_header.txt -destination=./mocks/mock_file.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client FileReader

import "os"

type fileReader interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]os.DirEntry, error)
}

type osFileReader struct{}

func newOSFileReader() fileReader {
	return &osFileReader{}
}

func (r *osFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (r *osFileReader) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
}
