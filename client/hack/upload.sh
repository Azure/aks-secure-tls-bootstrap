#!/bin/bash
set -euxo pipefail

[ -z "${STORAGE_ACCOUNT_SUBSCRIPTION:-}" ] && echo "STORAGE_ACCOUNT_SUBSCRIPTION must be specified" && exit 1
[ -z "${STORAGE_ACCOUNT_RESOURCE_GROUP:-}" ] && echo "STORAGE_ACCOUNT_RESOURCE_GROUP must be specified" && exit 1
[ -z "${STORAGE_ACCOUNT_NAME:-}" ] && echo "STORAGE_ACCOUNT_NAME must be specified" && exit 1
[ -z "${VERSION:-}" ] && echo "VERSION must be specified" && exit 1

OS="${OS:-linux}"

display_download_url() {
    local relpath="$1"
    web_endpoint=$(az storage account show -g $STORAGE_ACCOUNT_RESOURCE_GROUP -n $STORAGE_ACCOUNT_NAME --subscription $STORAGE_ACCOUNT_SUBSCRIPTION --query primaryEndpoints.web | tr -d \")
    echo "client download URL: ${web_endpoint}${relpath}"
}

build_and_upload_linux_amd64() {
    make build OS=linux ARCH=amd64 VERSION="${VERSION}"

    if [ ! -f "bin/aks-secure-tls-bootstrap-client-amd64" ]; then
        echo "could not find client binary aks-secure-tls-bootstrap-client-amd64 for upload within bin/"
        exit 1
    fi

    pushd "bin/"
        client_path="aks-secure-tls-bootstrap-client"
        mv "${client_path}-amd64" "$client_path"
        tar_path="linux-amd64.tar.gz"
        tar -czvf "$tar_path" "$client_path"
        az storage blob upload -f "$tar_path" --auth-mode login --blob-url "https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/\$web/client/linux/amd64/${VERSION}.tar.gz"
    popd

    rm -rf "bin/"

    display_download_url "client/linux/amd64/${VERSION}.tar.gz"
}

build_and_upload_windows_amd64() {
    make build OS=windows ARCH=amd64 EXTENSION=.exe VERSION="${VERSION}"

    if [ ! -f "bin/aks-secure-tls-bootstrap-client-amd64.exe" ]; then
        echo "could not find client binary aks-secure-tls-bootstrap-client-amd64.exe for upload within bin/"
        exit 1
    fi

    pushd "bin/"
        client_path="aks-secure-tls-bootstrap-client-amd64.exe"
        mv "${client_path}" "aks-secure-tls-bootstrap-client.exe"
        zip -r "windows-amd64.zip" "aks-secure-tls-bootstrap-client.exe"
        az storage blob upload -f "windows-amd64.zip" --auth-mode login --blob-url "https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/\$web/client/windows/amd64/${VERSION}.zip"
    popd

    rm -rf "bin/"

    display_download_url "client/windows/amd64/${VERSION}.zip"
}

if [ "${OS}" == "all" ]; then
    build_and_upload_linux_amd64
    build_and_upload_windows_amd64
elif [ "${OS}" == "linux" ]; then
    build_and_upload_linux_amd64
elif [ "${OS}" == "windows" ]; then
    build_and_upload_windows_amd64
else
    echo "unsupported OS: $OS, must be \"all\", \"linux\" or \"windows\""
    exit 1
fi
