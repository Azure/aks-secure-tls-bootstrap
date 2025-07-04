#!/bin/bash
set -euxo pipefail

# this script can be used to install an arbitrary version of aks-secure-tls-bootstrap-client
# on a running AKS node for development/testing.

STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-}"
VERSION="${VERSION:-}"
[ -z "$VERSION" ] && echo "VERSION must be specified" && exit 1
[ -z "$STORAGE_ACCOUNT_NAME" ] && echo "STORAGE_ACCOUNT_NAME must be specified" && exit 1

curl -fsSL https://${STORAGE_ACCOUNT_NAME}.z22.web.core.windows.net/client/linux/amd64/${VERSION} -o linux-amd64.tar.gz
mkdir -p client
tar -xvzf linux-amd64.tar.gz -C client
rm /usr/local/bin/aks-secure-tls-bootstrap-client
chmod +x client/aks-secure-tls-bootstrap-client
mv client/aks-secure-tls-bootstrap-client /usr/local/bin/aks-secure-tls-bootstrap-client
rm -rf client