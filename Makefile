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
fmt: fmt-client

.PHONY: vet
vet: vet-client

.PHONY: fmt-client
fmt-client:
	pushd $(PROJECT_DIR)/client && go fmt ./... && popd

.PHONY: vet-client
vet-client:
	pushd $(PROJECT_DIR)/client && go vet ./... && popd

.PHONY: test
test: test-client

.PHONY: coverage
coverage: test-coverage-client

.PHONY: test-client
test-client: ## Test all applicable go packages within the client module.
	pushd $(PROJECT_DIR)/client && go test $(shell go list ./... | grep -v proto | grep -v vendor | grep -v mock) && popd

.PHONY: test-coverage-client
test-coverage-client: ## Test all applicable go packages within the client module and calculate coverage.
	pushd $(PROJECT_DIR)/client && go test $(shell go list ./... | grep -v proto | grep -v vendor | grep -v mock) -coverprofile coverage_raw.out -covermode count && popd

.PHONY: protobuf
protobuf: # Generates protobuf implementation files within the service module.
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pkg/protos/bootstrap.proto

.PHONY: generate
generate: mockgen ## Generates gomocks in both the service and client modules.
	bin/mockgen \
		-copyright_file=hack/copyright_header.txt \
		-source=service/protos/bootstrap_grpc.pb.go \
		-destination=service/protos/mocks/mock_client.go \
		-package=mocks github.com/Azure/aks-secure-tls-bootstrap/service/protos \
		SecureTLSBootstrapServiceClient
	pushd $(PROJECT_DIR)/client && go generate ./... && popd

mockgen:
	$(call go-install-tool,$(PROJECT_DIR)/bin/mockgen,go.uber.org/mock/mockgen@v0.2.0)

##@ Build

.PHONY: build-client-all
build-client-all: fmt vet ## Builds the client binary for all platforms/architectures.
	@$(MAKE) build-client-linux ARCH=amd64
	@$(MAKE) build-client-linux ARCH=arm64
	@$(MAKE) build-client-windows ARCH=amd64
	@$(MAKE) build-client-windows ARCH=arm64

.PHONY: build-client-linux
build-client-linux: ## Builds the client binary for the specified linux architecture.
	pushd $(PROJECT_DIR)/client && CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/tls-bootstrap-client-$(ARCH) cmd/main.go && popd

.PHONY: build-client-windows
build-client-windows: ## Builds the client binary for the specified windows architecture.
	pushd $(PROJECT_DIR)/client && CGO_ENABLED=0 GOOS=windows GOARCH=$(ARCH) go build -o bin/tls-bootstrap-client-$(ARCH).exe cmd/main.go && popd

ifndef ignore-not-found
  ignore-not-found = false
endif

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