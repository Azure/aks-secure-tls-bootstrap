FROM mcr.microsoft.com/azurelinux/base/core:3.0

# Define build-time arguments for the protobuf versions
ARG GO_VERSION=1.23.6
ARG PROTOC_VERSION=28.3
ARG PROTOC_GEN_GO_VERSION=1.35.2

# Determine architecture and set appropriate URLs
RUN set -ex; \
    ARCH=`uname -m`; \
    tdnf install -y wget unzip tar ca-certificates; \
    if [ "$ARCH" = "x86_64" ]; then \
    PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"; \
    PROTOC_GEN_GO_URL="https://github.com/protocolbuffers/protobuf-go/releases/download/v${PROTOC_GEN_GO_VERSION}/protoc-gen-go.v${PROTOC_GEN_GO_VERSION}.linux.amd64.tar.gz"; \
    elif [ "$ARCH" = "aarch64" ]; then \
    PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-aarch_64.zip"; \
    PROTOC_GEN_GO_URL="https://github.com/protocolbuffers/protobuf-go/releases/download/v${PROTOC_GEN_GO_VERSION}/protoc-gen-go.v${PROTOC_GEN_GO_VERSION}.linux.arm64.tar.gz"; \
    else \
    echo "Unsupported architecture: $ARCH" && exit 1; \
    fi; \
    \
    # Download and install protobuf compiler
    wget -O protoc.zip $PROTOC_URL; \
    unzip protoc.zip -d /usr/local; \
    rm protoc.zip; \
    \
    # Download and install protobuf Go plugin
    wget -O protoc-gen-go.tar.gz $PROTOC_GEN_GO_URL; \
    tar -xzf protoc-gen-go.tar.gz -C /usr/local/bin; \
    rm protoc-gen-go.tar.gz; \
    \
    # Download and install Go
    curl -O "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"; \
    rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"; \
    rm "go${GO_VERSION}.linux-amd64.tar.gz"; \
    export PATH=$PATH:/usr/local/go/bin; \
    export GOPATH=/root/go && export PATH=$PATH:$GOPATH/bin; \
    go version; \
    \
    # Download and install the required grpc plugin
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
    protoc-gen-go-grpc -version

ENV PATH="$PATH:/root/go/bin"

# Default command
CMD ["protoc"]