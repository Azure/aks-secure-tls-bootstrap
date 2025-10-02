#!/bin/bash
set -euxo pipefail

[ -z "${VERSION:-}" ] && echo "VERSION must be specified" && exit 1
[ -z "${ARTIFACT_DIRECTORY:-}" ] && echo "ARTIFACT_DIRECTORY must be specified" && exit 1

LINUX_AMD64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-amd64"
LINUX_ARM64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-arm64"
WINDOWS_AMD64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-amd64.exe"

REPO_PATH="Azure/aks-secure-tls-bootstrap"

verify_artifacts() {
    if [ ! -f "${LINUX_AMD64_PATH}" ]; then
        echo "could not find linux-amd64 client binary artifact at: ${LINUX_AMD64_PATH}"
        exit 1
    fi
    if [ ! -f "${LINUX_ARM64_PATH}" ]; then
        echo "could not find linux-arm64 client binary artifact at: ${LINUX_ARM64_PATH}"
        exit 1
    fi
    if [ ! -f "${WINDOWS_AMD64_PATH}" ]; then
        echo "could not find windows-amd64 client binary artifact at: ${WINDOWS_AMD64_PATH}"
        exit 1
    fi
}

create_linux_tarballs() {
    CLIENT_PATH="aks-secure-tls-bootstrap-client"

    # create linux-amd64 tarball
    mv "${LINUX_AMD64_PATH}" "${CLIENT_PATH}"
    LINUX_AMD64_TAR="linux-amd64.tar.gz"
    tar -czvf "${LINUX_AMD64_TAR}" "${CLIENT_PATH}"

    # cleanup
    rm -f "${CLIENT_PATH}"

    # create linux-arm64 tarball
    mv "${LINUX_ARM64_PATH}" "${CLIENT_PATH}"
    LINUX_ARM64_TAR="linux-arm64.tar.gz"
    tar -czvf "${LINUX_ARM64_TAR}" "${CLIENT_PATH}"

    # cleanup
    rm -f "${CLIENT_PATH}"
}

create_windows_zip_archive() {
    CLIENT_PATH="aks-secure-tls-bootstrap-client.exe"

    #create windows-amd64 zip archive
    mv "${WINDOWS_AMD64_PATH}" "${CLIENT_PATH}"
    WINDOWS_AMD64_ZIP="windows-amd64.zip"
    zip -r "${WINDOWS_AMD64_ZIP}" "${CLIENT_PATH}"

    # cleanup
    rm -f "${CLIENT_PATH}"
}

create_github_release() {
    TAG_NAME="client/${VERSION}"
    echo "Creating GitHub release for tag: ${TAG_NAME}"
            
    # create the release
    CREATE_RELEASE_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        "https://api.github.com/repos/${REPO_PATH}/releases" \
        -d "{
            \"tag_name\": \"${TAG_NAME}\",
            \"name\": \"${TAG_NAME}\",
            \"draft\": false,
            \"prerelease\": false
        }")
    RELEASE_ID=$(echo "${CREATE_RELEASE_RESPONSE}" | jq -r '.id')
    UPLOAD_URL=$(echo "${CREATE_RELEASE_RESPONSE}" | jq -r '.upload_url')
    UPLOAD_URL="${UPLOAD_URL%\{*}"
    if [ -z "${RELEASE_ID}" ] || [ "${RELEASE_ID}" = "null" ] || [ -z "${UPLOAD_URL}" ] || [ "${UPLOAD_URL}" = "null" ]; then
        echo "Failed to create GitHub release. Response:"
        echo "${CREATE_RELEASE_RESPONSE}"
        exit 1
    fi
    
    echo "Created GitHub release with ID: ${RELEASE_ID}"
    
    # upload artifacts
    upload_asset "${UPLOAD_URL}" "${LINUX_AMD64_TAR}" "application/gzip"
    upload_asset "${UPLOAD_URL}" "${LINUX_ARM64_TAR}" "application/gzip"
    upload_asset "${UPLOAD_URL}" "${WINDOWS_AMD64_ZIP}" "application/zip"

    echo "Successfully created GitHub release for tag: ${TAG_NAME}"
    echo "Release URL: https://github.com/${REPO_PATH}/releases/tag/${TAG_NAME}"
}

upload_asset() {
    local upload_url="$1"
    local file_path="$2"
    local content_type="$3"
    local file_name=$(basename "${file_path}")
    
    echo "Uploading asset: ${file_name}"
    
    UPLOAD_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: ${content_type}" \
        "${upload_url}?name=${file_name}" \
        --data-binary "@${file_path}")
    
    # Check if upload was successful
    if [ "$(echo "${UPLOAD_RESPONSE}" | jq -r '.state')" = "uploaded" ]; then
        echo "Successfully uploaded: ${file_name}"
    else
        echo "Failed to upload asset: ${file_name}. Response:"
        echo "${UPLOAD_RESPONSE}"
        exit 1
    fi
}

verify_artifacts
create_linux_tarballs
create_windows_zip_archive
create_github_release