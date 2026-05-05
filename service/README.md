# Service

This module hosts the **Protobuf and gRPC contract** for the AKS Secure TLS Bootstrap service. It is the source of truth shared between the bootstrap client (in this repo, under [../client](../client)) and the AKS-hosted bootstrap server.

For repo-wide context, see the [root README](../README.md).

## What lives here

This module **does not** contain a server implementation — the bootstrap server is operated by AKS. What it ships is:

- The `.proto` definitions describing the wire format and RPC surface.
- The generated Go types and gRPC client/server stubs consumed by the client module.
- Generated [`gomock`](https://github.com/uber-go/mock) doubles for the gRPC client interface, used in client unit tests.

```
proto/akssecuretlsbootstrap/v1/
  service.proto         SecureTLSBootstrapService gRPC service definition
  nonce.proto           GetNonceRequest / GetNonceResponse messages
  credential.proto      GetCredentialRequest / GetCredentialResponse messages

pkg/gen/akssecuretlsbootstrap/v1/
  service.pb.go         Generated message types (proto)
  nonce.pb.go
  credential.pb.go
  service_grpc.pb.go    Generated gRPC client + server interfaces

pkg/gen/mock/akssecuretlsbootstrap/v1/
  service.go            gomock implementation of the gRPC client interface
```

The Go import path for the generated stubs is:

```go
import v1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
```

## API surface

The current `v1` service exposes two RPCs (see [proto/akssecuretlsbootstrap/v1/service.proto](proto/akssecuretlsbootstrap/v1/service.proto)):

| RPC | Purpose |
| --- | --- |
| `GetNonce(GetNonceRequest) → GetNonceResponse` | Issues a fresh nonce that the client must forward to IMDS when requesting attested data. Tying the nonce to the subsequent `GetCredential` call prevents replay of attested data documents. |
| `GetCredential(GetCredentialRequest) → GetCredentialResponse` | Validates the supplied attested data + nonce + CSR, and (on success) returns a signed kubelet client certificate PEM. |

Field annotations marked `(servicehub.fieldoptions.loggable) = false` use the [buf.build/service-hub/loggable](https://buf.build/service-hub/loggable) extension to mark sensitive fields (attested data, CSR, certificate PEMs) as redacted in any log emitted by a `loggable`-aware logger.

## Versioning

- The module is published under `github.com/Azure/aks-secure-tls-bootstrap/service`.
- Tags follow the pattern `service/vX.Y.Z`.
- Backwards-incompatible proto changes must be introduced under a new package version directory (`v2/...`); breaking changes to `v1` are blocked in CI by `buf breaking` (see below).

## Development

### Prerequisites

- Go 1.24+
- `make`
- [Docker](https://www.docker.com/) — `make generate` runs the [bufbuild/buf](https://hub.docker.com/r/bufbuild/buf) image to format, lint, and generate from the proto sources without requiring a local `buf` install.

### Common make targets

```sh
make generate          # proto-generate + proto-lint + mock-generate
make proto-generate    # buf format -w, build, dep update, generate
make proto-lint        # buf lint + buf breaking against main
make mock-generate     # regenerate gomock doubles for the gRPC client
```

The buf configuration is split between:

- [buf.yaml](buf.yaml) — module declaration, lint/breaking rule sets (`STANDARD` + `FILE`-level breaking), declared deps.
- [buf.gen.yaml](buf.gen.yaml) — remote `protoc-gen-go` and `protoc-gen-go-grpc` plugins, and the Go package prefix override.

### Workflow when changing the contract

1. Edit files under [proto/akssecuretlsbootstrap/v1/](proto/akssecuretlsbootstrap/v1/).
2. Run `make generate` — this will:
   - Format protos in-place.
   - Re-resolve `buf.build/service-hub/loggable` and other deps.
   - Regenerate `pkg/gen/...` Go sources.
   - Regenerate the mock client at `pkg/gen/mock/...`.
3. Run `make proto-lint` (also run by [.github/workflows/service-buf.yaml](../.github/workflows/service-buf.yaml)). The `buf breaking` check compares your branch against `main` and will fail on incompatible changes to `v1`.
4. Commit the regenerated files alongside the proto edits — generated artifacts are checked in so downstream consumers of the Go module do not need a buf toolchain.
5. Tag and release `service/vX.Y.Z`, then bump the dependency in [../client/go.mod](../client/go.mod).

### Adding a new dependency

Add the dependency under `deps:` in [buf.yaml](buf.yaml) and re-run `make proto-generate`. The buf container will pull and pin the dep before generating.

### Why generated code is checked in

The `client` module imports the generated Go packages directly. Vendoring them in this module keeps `go get` / `go build` for the client free of any buf or Docker requirement, and ensures downstream consumers see exactly the stubs that were reviewed in PRs.