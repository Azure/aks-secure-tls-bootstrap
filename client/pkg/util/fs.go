// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package util

//go:generate ../../../bin/mockgen -copyright_file=../../../hack/copyright_header.txt -destination=./mocks/mock_fs.go -package=mocks github.com/Azure/aks-secure-tls-bootstrap/client/pkg/util FS

import "os"

// FS provides a light-weight interface for interacting with a file system.
// Unit tests utilize mock implementations of this interface.
type FS interface {
	ReadFile(name string) ([]byte, error)
}

// OSFS provides an implementation of the FS interface using the os package.
type OSFS struct{}

var _ FS = &OSFS{}

func NewOSFS() *OSFS {
	return &OSFS{}
}

func (fs *OSFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}
