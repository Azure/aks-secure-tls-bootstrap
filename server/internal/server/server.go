// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package server

import (
	"context"
	"fmt"
	"net"

	v1 "github.com/Azure/aks-secure-tls-bootstrap/service/pkg/gen/akssecuretlsbootstrap/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Server is the gRPC server for the AKS secure TLS bootstrap service.
type Server struct {
	v1.UnimplementedSecureTLSBootstrapServiceServer

	logger     *zap.Logger
	grpcServer *grpc.Server
	health     *health.Server
	port       int
}

// New creates a new Server instance.
func New(logger *zap.Logger, port int) *Server {
	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()

	s := &Server{
		logger:     logger,
		grpcServer: grpcServer,
		health:     healthServer,
		port:       port,
	}

	v1.RegisterSecureTLSBootstrapServiceServer(grpcServer, s)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	return s
}

// Start starts the gRPC server and marks the service as ready.
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	// Mark the overall server and specific service as serving
	// so that liveness and readiness probes succeed once the server is ready.
	s.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	s.health.SetServingStatus(v1.SecureTLSBootstrapService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)

	s.logger.Info("starting gRPC server", zap.Int("port", s.port))

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down gRPC server")
		s.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		s.health.SetServingStatus(v1.SecureTLSBootstrapService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		s.grpcServer.GracefulStop()
	}()

	if err := s.grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("gRPC server failed: %w", err)
	}
	return nil
}
