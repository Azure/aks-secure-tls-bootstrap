#!/bin/bash
set -euxo pipefail

STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-}"
VERSION="${VERSION:-}"

[ -z "$STORAGE_ACCOUNT_NAME" ] && echo "STORAGE_ACCOUNT_NAME must be specified" && exit 1
[ -z "$VERSION" ] && echo "VERSION must be specified" && exit 1

function build_and_upload_linux_amd64() {
    rm -rf "bin/"
    make build OS=linux ARCH=amd64

    if [ ! -f "bin/aks-secure-tls-bootstrap-client-amd64" ]; then
        echo "could not find client binary aks-secure-tls-bootstrap-client-amd64 for upload within bin/"
        exit 1
    fi

    pushd "bin/"
        client_path="aks-secure-tls-bootstrap-client"
        mv "${client_path}-amd64" "$client_path"
        tar_path="linux-amd64.tar.gz"
        tar -czvf "$tar_path" "$client_path"
        az storage blob upload -f "$tar_path" --auth-mode login --blob-url "https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/\$web/client/linux/amd64/${VERSION}"
    popd
}

build_and_upload_linux_amd64