# Client

[![Go Report Card](https://goreportcard.com/badge/github.com/Azure/aks-secure-tls-bootstrap/client)](https://goreportcard.com/report/github.com/Azure/aks-secure-tls-bootstrap/client)
[![Unit Tests](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-coverage.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-coverage.yaml)
[![Binary Build](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-build.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-build.yaml)
[![golangci-lint](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-golangci-lint.yaml/badge.svg)](https://github.com/Azure/aks-secure-tls-bootstrap/actions/workflows/client-golangci-lint.yaml)

This module implements the AKS Secure TLS Bootstrap client, used as an alternative to [TLS bootstrapping](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/) for securely joining agent nodes to AKS control planes.