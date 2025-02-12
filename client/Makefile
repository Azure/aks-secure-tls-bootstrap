# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Default arch is amd64.
ARCH=amd64

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

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
	@$(MAKE) build-linux ARCH=amd64
	@$(MAKE) build-linux ARCH=arm64
	@$(MAKE) build-windows ARCH=amd64
	@$(MAKE) build-windows ARCH=arm64

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/aks-stls-bootstrap-client-$(ARCH) cmd/client/main.go

.PHONY: build-windows
build-windows: ## Builds the client binary for the specified windows architecture.
	CGO_ENABLED=0 GOOS=windows GOARCH=$(ARCH) go build -o bin/aks-stls-bootstrap-client-$(ARCH).exe cmd/client/main.go

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