# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# Go build parameter defaults.
ARCH=amd64
OS=linux

##@ Development

.PHONY: test
test:
	go test ./...

##@ Build

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o bin/aks-secure-tls-bootstrap-server cmd/server/main.go
