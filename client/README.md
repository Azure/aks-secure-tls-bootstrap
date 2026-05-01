# Client

[![Go Report Card](https://goreportcard.com/badge/github.com/Azure/aks-secure-tls-bootstrap/client)](https://goreportcard.com/report/github.com/Azure/aks-secure-tls-bootstrap/client)
[![Unit Tests](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-coverage.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-coverage.yaml)
[![Binary Build](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-build.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-build.yaml)
[![golangci-lint](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-golangci-lint.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-golangci-lint.yaml)

This module implements the **AKS Secure TLS Bootstrap client** — a single-shot CLI invoked on an AKS agent node to obtain a kubelet client credential, replacing the upstream [Kubernetes TLS bootstrap](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/) token-based flow with one rooted in Azure VM attestation and AAD (Entra ID).

For repo-wide context, see the [root README](../README.md).

## What the client does

When invoked, the client:

1. **Checks the existing kubeconfig.** If `--kubeconfig` already points to a valid (and optionally authorized) kubeconfig, the client exits successfully without contacting the bootstrap server.
2. **Acquires an AAD access token.** Uses the kubelet MSI defined in the cloud provider config (or `--user-assigned-identity-id` override) via [IMDS](https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service) for the AAD audience configured by `--aad-resource`.
3. **Opens a gRPC connection** to the bootstrap server identified by `--apiserver-fqdn`, pinned to the cluster CA at `--cluster-ca-file`, with the configured `--tls-min-version` and ALPN `--next-proto` value, authenticated by the AAD token.
4. **Fetches VM instance data** from IMDS to derive the VM's Azure Resource ID.
5. **`GetNonce`** — requests a fresh nonce from the server.
6. **Fetches attested data** from IMDS, signed over the nonce.
7. **Generates a kubelet client CSR** and matching private key on disk under `--cert-dir`.
8. **`GetCredential`** — submits the CSR + attested data; receives a signed kubelet client certificate.
9. **Writes a kubeconfig** at `--kubeconfig` referencing the new cert/key, suitable for direct consumption by the kubelet.

Each phase has its own configurable timeout and is recorded in the bootstrap [telemetry trace](internal/telemetry/telemetry.go) emitted as a guest-agent event.

## Package layout

```
cmd/client/main.go                CLI entrypoint, flag/config parsing, telemetry emission
internal/
  bootstrap/                      Bootstrap protocol orchestration
    bootstrap.go / client.go      Top-level Bootstrap() and step-by-step orchestrator
    auth.go                       AAD token acquisition (azidentity) + gRPC credentials
    config.go                     CLI/JSON config schema, defaults, validation
    csr.go                        Kubelet client CSR + private key generation
    grpc.go                       gRPC dial options, retry, ALPN setup
    event.go                      Guest-agent event payload writer
    errors.go                     Typed bootstrap errors and classification
  build/                          Version stamping (-ldflags injects build.version)
  cloud/                          Azure cloud provider config loader
  http/                           Shared HTTP client with retries
  imds/                           IMDS client (instance + attested data)
  kubeconfig/                     Kubeconfig generation + existing-kubeconfig validation
  log/                            zap logger wiring (file + console, verbose mode)
  telemetry/                      Span/trace tracking emitted in bootstrap result
  testutil/                       Cert/key fixtures used in tests
hack/
  upload.sh                       Cross-build + upload to Azure Storage
  linux/install.sh                Node-side installer (Linux) (FOR DEV PURPOSES ONLY)
  windows/install.ps1             Node-side installer (Windows) (FOR DEV PURPOSES ONLY)
```

## Installing on a node

Pre-built binaries are uploaded to an Azure Storage static-website endpoint by [hack/upload.sh](hack/upload.sh). The included installer scripts download and place the binary in the standard AKS locations:

**Linux** (`/opt/bin/aks-secure-tls-bootstrap-client`, mirrored to `/usr/local/bin`):

```sh
curl -o install.sh https://raw.githubusercontent.com/Azure/aks-secure-tls-bootstrap/refs/heads/main/client/hack/linux/install.sh
chmod +x install.sh
VERSION=<version> STORAGE_ACCOUNT_NAME=<storage-account> ./install.sh
```

**Windows** (`C:\k\aks-secure-tls-bootstrap-client.exe`):

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/aks-secure-tls-bootstrap/refs/heads/main/client/hack/windows/install.ps1" -OutFile install.ps1
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\install.ps1 -Version <version> -StorageAccountName <storage-account>
```

## Usage

The client accepts both CLI flags and a JSON config file via `--config-file` (file values override flag values). The full flag set is documented by `aks-secure-tls-bootstrap-client -h`.

### Required configuration

| Flag | JSON key | Description |
| --- | --- | --- |
| `--cloud-provider-config` | `cloudProviderConfigPath` | Path to the AKS cloud provider config (used to resolve the kubelet MSI). |
| `--apiserver-fqdn` | `apiServerFqdn` | FQDN of the bootstrap-enabled API server. |
| `--aad-resource` | `aadResource` | Audience for the AAD token request to IMDS. |
| `--next-proto` | `nextProto` | ALPN `next-proto` header value expected by the bootstrap server. |
| `--cluster-ca-file` | `clusterCaFilePath` | Path to the cluster CA bundle used to verify the bootstrap server. |
| `--kubeconfig` | `kubeconfigPath` | Output kubeconfig path; must match kubelet's `--kubeconfig`. |
| `--cert-dir` | `certDir` | Directory for new client cert/key pair; must match kubelet's `--cert-dir`. |

### Useful optional flags

| Flag | Default | Description |
| --- | --- | --- |
| `--user-assigned-identity-id` | _from cloud provider config_ | Override the MSI client ID used for IMDS token requests. |
| `--tls-min-version` | `1.3` | Minimum TLS version (`1.2` or `1.3`). |
| `--ensure-authorized` | `false` | If set, validate that the existing kubeconfig is not just structurally valid but authorized against the API server. |
| `--validate-kubeconfig-timeout` | `15s` | Timeout for the existing-kubeconfig validation step. |
| `--get-access-token-timeout` | `1m` | Timeout for the IMDS token request. |
| `--get-instance-data-timeout` | `15s` | Timeout for IMDS instance metadata fetch. |
| `--get-nonce-timeout` | `15s` | Timeout for the `GetNonce` RPC. |
| `--get-attested-data-timeout` | `15s` | Timeout for IMDS attested data fetch. |
| `--get-credential-timeout` | `6m` | Timeout for the `GetCredential` RPC. |
| `--log-file` | _stdout only_ | Mirror logs to a file. |
| `--verbose` | `false` | Emit debug-level logs. |

`--deadline` is deprecated in favor of the per-RPC timeouts above and is retained only for backwards compatibility.

### Example

```sh
aks-secure-tls-bootstrap-client \
  --cloud-provider-config=/etc/kubernetes/azure.json \
  --apiserver-fqdn=my-cluster-1234.hcp.eastus.azmk8s.io \
  --aad-resource=6dae42f8-4368-4678-94ff-3960e28e3630 \
  --next-proto=aks-tls-bootstrap \
  --cluster-ca-file=/etc/kubernetes/certs/ca.crt \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  --cert-dir=/var/lib/kubelet/pki \
  --tls-min-version=1.3 \
  --ensure-authorized
```

The process exits `0` on success (kubeconfig either already valid or freshly written) and `1` on any failure. Failure classifications (e.g. `GetAccessTokenFailure`, `GetCredentialFailure`) are recorded in the emitted guest-agent event for downstream telemetry.

## Development

### Prerequisites

- Go 1.24+ (matches `go.mod`)
- `make`
- [`golangci-lint`](https://golangci-lint.run/) for local linting (CI uses [.github/workflows/client-golangci-lint.yaml](../.github/workflows/client-golangci-lint.yaml))

### Common make targets

```sh
make test                # go test ./...
make test-coverage       # produces coverage_raw.out
make generate            # regenerates gomock-based mocks (installs mockgen into bin/)
make build               # OS=linux ARCH=amd64 (default), CGO disabled
make build OS=linux ARCH=arm64
make build OS=windows ARCH=amd64 EXTENSION=.exe
make build-all           # builds all supported OS/ARCH combos
make build-prod          # CGO_ENABLED=1 GOEXPERIMENT=systemcrypto for FIPS-compliant builds
```

The `VERSION` value is derived from `git describe` and stamped into the binary via `-ldflags` against [internal/build/build.go](internal/build/build.go); pass `VERSION=...` to override.

### Mocks

Interface mocks live alongside the package they mock under `mocks/` subdirectories (e.g. [internal/imds/mocks/mock_imds.go](internal/imds/mocks/mock_imds.go)). They are generated by [`go.uber.org/mock/mockgen`](https://github.com/uber-go/mock) via `//go:generate` directives; run `make generate` after changing an interface.

### Adding or changing the bootstrap protocol

The client depends on the gRPC stubs generated from [../service/proto](../service/proto). When the proto contract changes:

1. Update the proto files and run `make generate` in [../service](../service).
2. Tag and release a new version of the `service` module.
3. Bump the dependency in this module's [go.mod](go.mod) and adjust call sites under [internal/bootstrap/](internal/bootstrap/).

### Releasing binaries

Cross-builds are uploaded by [hack/upload.sh](hack/upload.sh), which expects:

```sh
STORAGE_ACCOUNT_SUBSCRIPTION=<sub-id> \
STORAGE_ACCOUNT_RESOURCE_GROUP=<rg> \
STORAGE_ACCOUNT_NAME=<storage-account> \
VERSION=<semver> \
OS=all \   # or linux | windows
./hack/upload.sh
```

The script invokes `make build` per target, archives the binary (`tar.gz` for Linux, `zip` for Windows), and uploads to the `$web` container of the configured storage account, where it is consumed by the install scripts above.