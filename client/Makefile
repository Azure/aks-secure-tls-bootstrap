# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# Go build parameter defaults.
VERSION := $(shell VERSION=$$(git describe --tags --match "client/*" --abbrev=8 --dirty --always --long) && echo $${VERSION//client\//})
BUILD_PACKAGE_PREFIX=github.com/Azure/aks-secure-tls-bootstrap/client/internal/build
LDFLAGS="-X '$(BUILD_PACKAGE_PREFIX).Version=$(VERSION)'"
ARCH=amd64
OS=linux
EXTENSION=

##@ Development

.PHONY: test
test:
	go test $(shell go list ./... | grep -v vendor | grep -v mock | grep -v testutil)

.PHONY: test-coverage
test-coverage:
	go test $(shell go list ./... | grep -v vendor | grep -v mock | grep -v testutil) -coverprofile coverage_raw.out -covermode count

.PHONY: generate
generate: mockgen
	go generate ./...

mockgen:
	$(call go-install-tool,$(PROJECT_DIR)/bin/mockgen,go.uber.org/mock/mockgen@v0.5.0)

##@ Build

.PHONY: build-all
build-all:
	@$(MAKE) build OS=linux ARCH=amd64
	@$(MAKE) build OS=linux ARCH=arm64
	@$(MAKE) build OS=windows ARCH=amd64 EXTENSION=.exe
	@$(MAKE) build OS=windows ARCH=arm64 EXTENSION=.exe

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags $(LDFLAGS) -o bin/aks-stls-bootstrap-client-$(ARCH)$(EXTENSION) cmd/client/main.go

##@ Util

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
	set -e ;\
	TMP_DIR=$$(mktemp -d) ;\
	cd $$TMP_DIR ;\
	go mod init tmp ;\
	echo "Downloading $(2)" ;\
	GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
	rm -rf $$TMP_DIR ;\
}
endef

# go-install-tool will 'go install' any package $2 and install it to $1.
define go-install-tool
@[ -f $(1) ] || { \
	set -e ;\
	echo "Downloading $(2)" ;\
	GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
}
endef