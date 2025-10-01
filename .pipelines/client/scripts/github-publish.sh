#!/bin/bash
set -euxo pipefail

[ -z "${VERSION:-}" ] && echo "VERSION must be specified" && exit 1
[ -z "${ARTIFACT_DIRECTORY:-}" ] && echo "ARTIFACT_DIRECTORY must be specified" && exit 1

LINUX_AMD64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-amd64"
LINUX_ARM64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-arm64"
WINDOWS_AMD64_PATH="${ARTIFACT_DIRECTORY}/aks-secure-tls-bootstrap-client-amd64.exe"

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
    TAG_NAME="client/v${VERSION}"
    echo "Creating GitHub release for tag: ${TAG_NAME}"
    
    RELEASE_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        "https://api.github.com/repos/Azure/aks-secure-tls-bootstrap/releases" \
        -d "{
            \"tag_name\": \"${TAG_NAME}\",
            \"name\": \"${TAG_NAME}\",
            \"body\": \"official client release - v${VERSION}\",
            \"draft\": false,
            \"prerelease\": false
        }")
    
    # Extract release ID and upload URL
    RELEASE_ID=$(echo "${RELEASE_RESPONSE}" | grep -o '"id":[[:space:]]*[0-9]\+' | head -1 | grep -o '[0-9]\+')
    UPLOAD_URL=$(echo "${RELEASE_RESPONSE}" | grep -o '"upload_url":[[:space:]]*"[^"]\+"' | grep -o 'https://[^"]\+')
    UPLOAD_URL="${UPLOAD_URL%\{*}"  # Remove the {?name,label} template part
    
    if [ -z "${RELEASE_ID}" ] || [ -z "${UPLOAD_URL}" ]; then
        echo "Failed to create GitHub release. Response:"
        echo "${RELEASE_RESPONSE}"
        exit 1
    fi
    
    echo "Created GitHub release with ID: ${RELEASE_ID}"
    
    # Upload artifacts
    upload_asset "${UPLOAD_URL}" "${LINUX_AMD64_TAR}" "application/gzip"
    upload_asset "${UPLOAD_URL}" "${LINUX_ARM64_TAR}" "application/gzip"
    upload_asset "${UPLOAD_URL}" "${WINDOWS_AMD64_ZIP}" "application/zip"
    
    echo "Successfully created GitHub release: ${RELEASE_TAG}"
    echo "Release URL: https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/tag/${RELEASE_TAG}"
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
    if echo "${UPLOAD_RESPONSE}" | grep -q '"state":[[:space:]]*"uploaded"'; then
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
# create_github_release