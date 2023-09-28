# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

ARCH=amd64

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: fmt-vet
fmt-vet:
	@$(MAKE) fmt
	@$(MAKE) vet

.PHONY: test
test: ## Test all applicable go packages.
	go test $(shell go list ./pkg... | grep -v proto | grep -v vendor | grep -v mock)

.PHONY: test-coverage
test-coverage:
	go test $(shell go list ./pkg... | grep -v proto | grep -v vendor | grep -v mock) -coverprofile coverage_raw.out -covermode count

##@ Build

.PHONY: generate
generate: mockgen ## Run go generate against code.
	go generate ./...

.PHONY: protobuf
protobuf:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pkg/protos/bootstrap.proto

.PHONY: build-client-all
build-client-all: fmt vet ## Builds the client binary for all platforms
	@$(MAKE) build-client-linux ARCH=amd64
	@$(MAKE) build-client-linux ARCH=arm64
	@$(MAKE) build-client-windows ARCH=amd64
	@$(MAKE) build-client-windows ARCH=arm64

.PHONY: build-client-linux
build-client-linux: ## Builds a linux binary for the specified architecture
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/tls-bootstrap-client-$(ARCH) cmd/client/main.go

.PHONY: build-client-windows
build-client-windows: ## Builds a windows binary for the specified architecture
	CGO_ENABLED=0 GOOS=windows GOARCH=$(ARCH) go build -o bin/tls-bootstrap-client-$(ARCH).exe cmd/client/main.go

.PHONY: build
build: fmt vet # Build client binary
	go build -o bin/tls-bootstrap-client cmd/client/main.go

mockgen:
	$(call go-install-tool,$(PROJECT_DIR)/bin/mockgen,go.uber.org/mock/mockgen@v0.2.0)

ifndef ignore-not-found
  ignore-not-found = false
endif

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