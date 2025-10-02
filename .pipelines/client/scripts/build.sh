#!/bin/bash
set -euxo pipefail

[ -z "${VERSION:-}" ] && echo "VERSION must be specified" && exit 1
[ -z "${OS:-}" ] && echo "OS must be specified" && exit 1
[ -z "${ARCH:-}" ] && echo "ARCH must be specified" && exit 1
[ -z "${STAGING_DIRECTORY:-}" ] && echo "STAGING_DIRECTORY must be specified" && exit 1

EXTENSION="${EXTENSION:-}"

# checkout the particular tag we'd like to build
git checkout client/${VERSION}

# run unit tests
cd client && make test

# build the binary for the target OS/arch
LDFLAGS="-X github.com/Azure/aks-secure-tls-bootstrap/client/internal/build.version=${VERSION}"
make build-prod OS="${OS}" ARCH="${ARCH}" EXTENSION="${EXTENSION}" LDFLAGS="${LDFLAGS}"

BIN_PATH="bin/aks-secure-tls-bootstrap-client-${ARCH}${EXTENSION}"
if [ ! -f "${BIN_PATH}" ]; then
    echo "binary ${BIN_PATH} is missing after building with make"
    exit 1
fi

# we can only test linux binaries since we're using Ubuntu-based build agents
if [ "${OS,,}" = "linux" ]; then
    set +e
    sudo chmod +x "${BIN_PATH}"
    HELP_OUTPUT=$(sudo ./${BIN_PATH} -h 2>&1)
    EXIT_CODE=$?
    set -e

    if [ $EXIT_CODE -ne 0 ]; then
        echo "failed to run help command on newly-built binary, exit code: ${EXIT_CODE}"
        exit 1
    fi

    if [[ "${HELP_OUTPUT}" != *"${VERSION}"* ]]; then
        echo "help command output did not contain expected version string: \"${VERSION}\""
        exit 1
    fi
fi

# move the newly-built binary to the staging directory
mv "${BIN_PATH}" "${STAGING_DIRECTORY}/aks-secure-tls-bootstrap-client-${ARCH}${EXTENSION}"