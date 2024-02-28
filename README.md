# aks-secure-tls-bootstrap

[![Test coverage](https://github.com/Azure/aks-tls-bootstrap-client/actions/workflows/check-coverage.yaml/badge.svg)](https://github.com/Azure/aks-tls-bootstrap-client/actions/workflows/check-coverage.yaml)
[![Coverage Status](https://coveralls.io/repos/github/Azure/aks-tls-bootstrap-client/badge.svg?branch=main)](https://coveralls.io/github/Azure/aks-tls-bootstrap-client?branch=main)

[![golangci-lint](https://github.com/Azure/aks-tls-bootstrap-client/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/Azure/aks-tls-bootstrap-client/actions/workflows/golangci-lint.yaml)

This repo contains the following:

- The [client](client/) module, which makes up the implementation of the AKS secure TLS bootstrap client.
- The [service](service/) module, which holds and makes available the proto definitions used by the client to communicate with the bootstrap server.

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

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

## Testing

ginko is used for unit tests.

### setting up goproxy
ado token: https://dev.azure.com/msazure/_usersSettings/tokens
```
vim ~./zshrc # bashrc 
export AKS_GOPROXY_TOKEN=******
export GOPROXY=https://<username>:$AKS_GOPROXY_TOKEN@goproxyprod.goms.io
soruce ~./zshrc
```


Unit tests are available inside client/pkgs/
### To run the full suite
```
tls_bootstrapping/aks-secure-tls-bootstrap/client/pkg % go test ./... -coverprofile cover.out 
# To see the unit test coverage
go tool cover -html=cover.out
```