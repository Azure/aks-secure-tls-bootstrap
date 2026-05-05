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
