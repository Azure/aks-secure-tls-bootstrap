# aks-secure-tls-bootstrap

This repository hosts a subset of the components that implement **AKS Secure TLS Bootstrapping**, an Azure-native alternative to the upstream Kubernetes [TLS bootstrap](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/) flow used to securely join agent nodes to an AKS cluster.

## Repository layout

| Path | Description |
| --- | --- |
| [client/](client/) | Go module implementing the bootstrap client binary that runs on AKS nodes. See [client/README.md](client/README.md). |
| [service/](service/) | Go module containing the Protobuf/gRPC contract (`SecureTLSBootstrapService`) shared between client and server. See [service/README.md](service/README.md). |
| [hack/](hack/) | Shared developer utilities (e.g. license headers used by code generators). |
| [.github/workflows/](.github/workflows/) | CI for unit tests, binary builds, golangci-lint, CodeQL, and `buf` proto checks. |

The two Go modules are versioned and released independently:

- `github.com/Azure/aks-secure-tls-bootstrap/client`
- `github.com/Azure/aks-secure-tls-bootstrap/service`

The client depends on the service module for generated gRPC stubs.

## Getting started

### Prerequisites

- [Go](https://go.dev/dl/) 1.24+
- `make`
- [Docker](https://www.docker.com/) (only required when regenerating Protobuf/gRPC code via [`buf`](https://buf.build/))

### Build the client

```sh
cd client
make build                              # default: linux/amd64 -> bin/aks-secure-tls-bootstrap-client-amd64
make build OS=linux ARCH=arm64
make build OS=windows ARCH=amd64 EXTENSION=.exe
make build-all                          # all supported OS/ARCH combinations
```

### Run the test suites

```sh
# client unit tests
cd client && make test

# regenerate proto + mocks (requires Docker)
cd service && make generate
```

See the per-module READMEs for more details:

- [client/README.md](client/README.md) — building, testing, configuration, deployment.
- [service/README.md](service/README.md) — proto layout, code generation, versioning.

## Releases

- **Client binaries** are tagged with `client/vX.Y.Z` and published as compressed archives to a configured Azure Storage static-website endpoint via [client/hack/upload.sh](client/hack/upload.sh). Install scripts for nodes are provided in [client/hack/linux/install.sh](client/hack/linux/install.sh) and [client/hack/windows/install.ps1](client/hack/windows/install.ps1).
- **Service module** releases are tagged with `service/vX.Y.Z` and consumed by the client `go.mod` as a regular Go module dependency.

## Security

Please see [SECURITY.md](SECURITY.md) for the supported reporting process. Do not file public GitHub issues for security vulnerabilities.

## Support

See [SUPPORT.md](SUPPORT.md) for how to file bugs, request features, and ask questions.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

### Signing your commits

This is an example that has been tested on WSL Ubuntu 22.04 and Ubuntu 22.04. For Mac and Windows powershell it should be similar.

1. List an existing key on your local machine. `gpg --list-secret-keys --keyid-format=long`
   - If it's empty or if you want to use a new one, run `gpg --default-new-key-algo rsa4096 --gen-key`

2. Create a PGP Public key by running this command
   `gpg --armor --export <GPG Key ID>` where the GPG Key ID is the one you got from step 1.

   For more info, check step 3 in this doc. [Associating an email with your GPG key - GitHub Docs](https://docs.github.com/en/authentication/managing-commit-signature-verification/associating-an-email-with-your-gpg-key)

3. Finally add the public key to github by following this doc. https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account#adding-a-gpg-key

4. Re-do the commit with the correct command. `git commit -S -m "YOUR_COMMIT_MESSAGE"` and it should work now.

   - If you encounter error `gpg: signing failed: Inappropriate ioctl for device`, follow the below
   ``` git config --global gpg.program gpg
   git config --global commit.gpgsign true
   git config --global gpg.passphrase "<the passphrase you set in step 1 if you created a new one>"
   echo "use-agent" >> ~/.gnupg/gpg.conf
   echo "pinentry-mode loopback" >> ~/.gnupg/gpg.conf
   echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
   gpgconf --kill gpg-agent
   gpgconf --launch gpg-agent
   ```
5. (Optional but recommended) Run `git config commit.gpgsign true` to config it to always sign with gpg in this repo.

Note: if you have previously pushed unsigned commit, you can try the following.

- run `git commit --amend -s`. You should see no errors.
    - `git rebase HEAD~<number of your commits on branch> --signoff` for multiple commits
- run `git push --force`. This should overwrite your previous commit with the new signed commit on remote branch/PR.

#### More reference
- https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits

- https://docs.github.com/en/authentication/managing-commit-signature-verification/associating-an-email-with-your-gpg-key

- https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account#adding-a-gpg-key

### Contributor workflow

1. Clone the repo. We don't currently accept contributions from personal forks, this you'll need write access directly to this repository to make any contributions. Write access will require membership to the [Azure GitHub organization](https://github.com/azure).
2. Make changes within `client/` or `service/` (each is a self-contained Go module).
3. Run the relevant `make test` / `make generate` / lint targets locally.
4. Ensure the corresponding GitHub Actions workflows pass on your PR.
5. Add or update unit tests for any behavioral change.
6. Keep file headers consistent with [hack/copyright_header.txt](hack/copyright_header.txt).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.