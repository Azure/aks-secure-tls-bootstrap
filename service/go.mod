module github.com/Azure/aks-secure-tls-bootstrap/service

go 1.24.0

require (
	buf.build/gen/go/service-hub/loggable/protocolbuffers/go v1.36.5-20231012175355-a349f6324a7e.1
	go.uber.org/mock v0.5.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.10
)

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
