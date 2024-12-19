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

##@ Development

.PHONY: protobuf
protobuf:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative protos/bootstrap.proto

.PHONY: generate
generate: mockgen
	bin/mockgen \
		-copyright_file=$(PROJECT_DIR)/../hack/copyright_header.txt \
		-source=protos/bootstrap_grpc.pb.go \
		-destination=protos/mocks/mock_client.go \
		-package=mocks github.com/Azure/aks-secure-tls-bootstrap/service/protos \
		SecureTLSBootstrapServiceClient

mockgen:
	$(call go-install-tool,$(PROJECT_DIR)/bin/mockgen,go.uber.org/mock/mockgen@v0.2.0)

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