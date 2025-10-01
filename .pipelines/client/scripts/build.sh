#!/bin/bash
set -euxo pipefail

[ -z "${VERSION:-}" ] && echo "VERSION must be specified" && exit 1
[ -z "${REVISION:-}" ] && echo "REVISION must be specified" && exit 1
[ -z "${OS:-}" ] && echo "OS must be specified" && exit 1
[ -z "${ARCH:-}" ] && echo "ARCH must be specified" && exit 1
[ -z "${STAGING_DIRECTORY:-}" ] && echo "STAGING_DIRECTORY must be specified" && exit 1

EXTENSION="${EXTENSION:-}"

# checkout the particular tag we'd like to build
git checkout client/${VERSION}

# build the binary for the target OS/arch
cd client
LDFLAGS="-X github.com/Azure/aks-secure-tls-bootstrap/client/internal/build.version=${VERSION}-${REVISION}"
make build-prod OS="${OS}" ARCH="${ARCH}" EXTENSION="${EXTENSION}" LDFLAGS="${LDFLAGS}"

BIN_PATH="bin/aks-secure-tls-bootstrap-client-${ARCH}${EXTENSION}"
if [ ! -f "${BIN_PATH}" ]; then
    echo "binary ${BIN_PATH} is missing after building with make"
    exit 1
fi

# move the newly-built binary to the staging directory
mv "${BIN_PATH}" "${STAGING_DIRECTORY}/aks-secure-tls-bootstrap-client${EXTENSION}"