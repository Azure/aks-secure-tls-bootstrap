#!/bin/bash
set -euxo pipefail

STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-}"
VERSION="${VERSION:-}"

[ -z "$STORAGE_ACCOUNT_NAME" ] && echo "STORAGE_ACCOUNT_NAME must be specified" && exit 1
[ -z "$VERSION" ] && echo "VERSION must be specified" && exit 1

function build_and_upload_linux_amd64() {
    make build OS=linux ARCH=amd64
    client_path="$(pwd)/bin/aks-secure-tls-bootstrap-client-amd64"
    [ ! -f "$client_path" ] && echo "could not find client binary for upload at $client_path" && exit 1
    az storage blob upload -f "$client_path" --auth-mode login --blob-url "https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/\$web/client/amd64/${VERSION}"
}

build_and_upload_linux_amd64