# Run buf in docker, mounting the full repo into the container
# Emulate running "buf" in the current directory
BUF = docker run --volume "$(CURDIR)/../:$(CURDIR)/../" --workdir $(CURDIR) bufbuild/buf:1.47.2

.PHONY: generate
generate: proto-generate proto-lint mock-generate

.PHONY: proto-generate
proto-generate:
	@($(BUF) format -w)
	rm -rf pkg/gen/service/v1
	docker build --platform $(shell uname -m) -t protoc-docker - < protoc.Dockerfile
	docker run --rm -v $(shell pwd):/$(shell pwd) --workdir=$(shell pwd) protoc-docker protoc \
		--go_opt=module=github.com/Azure/aks-secure-tls-bootstrap/service \
		--go_out=. \
		--go-grpc_opt=module=github.com/Azure/aks-secure-tls-bootstrap/service \
		--go-grpc_out=. \
		--proto_path=proto  $(shell find proto/akssecuretlsbootstrap/v1 -name '*.proto')
	$(MAKE) proto-lint

.PHONY: proto-lint
proto-lint:
	@($(BUF) lint)
	@($(BUF) breaking --against '../.git#branch=main,subdir=service')

.PHONY: mock-generate
mock-generate: mockgen ## Generates gomocks in both the service and client modules.
	bin/mockgen \
		-package=mocks \
		-copyright_file=$(PROJECT_DIR)/../hack/copyright_header.txt \
		-source=pkg/gen/akssecuretlsbootstrap/v1/service_grpc.pb.go \
		-destination=pkg/mocks/akssecuretlsbootstrap/v1/service.go \
		github.com/Azure/aks-secure-tls-bootstrap/service/proto \
		SecureTLSBootstrapServiceClient

mockgen:
	$(call go-install-tool,$(PROJECT_DIR)/bin/mockgen,go.uber.org/mock/mockgen@v0.5.0)

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