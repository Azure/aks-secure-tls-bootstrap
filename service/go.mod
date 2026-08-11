module github.com/Azure/aks-secure-tls-bootstrap/service

go 1.25.0

require (
	buf.build/gen/go/service-hub/loggable/protocolbuffers/go v1.36.11-20231012175355-a349f6324a7e.1
	go.uber.org/mock v0.6.0
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260810153831-ec0a7760b754 // indirect
)
