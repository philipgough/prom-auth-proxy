package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	lbacserver "github.com/philipgough/prom-auth-proxy/internal/pkg/lbac"
	"github.com/philipgough/prom-auth-proxy/pkg/lbac"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var (
	configFile string
	grpcPort   int
)

type healthServer struct{}

func (s *healthServer) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func main() {
	flag.Parse()

	var policies lbac.Policies
	if configFile != "" {
		// if we have a config file, read the policies from it
		// if not we expect the policies to be in the metadata
		b, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Error reading config file: %v", err)
		}

		p, err := lbac.RawPolicyToPolicy(b)
		if err != nil {
			log.Fatalf("Error converting raw policy to policy: %v", err)
		}
		policies = p
	}

	endPoint := fmt.Sprintf(":%d", grpcPort)
	listen, err := net.Listen("tcp", endPoint)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}

	opts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	s := grpc.NewServer(opts...)

	pb.RegisterExternalProcessorServer(s, lbacserver.NewServer(policies))
	healthpb.RegisterHealthServer(s, &healthServer{})
	log.Print("Starting gRPC server")
	s.Serve(listen)
}

func init() {
	flag.StringVar(&configFile, "policy-config", "",
		"Path to the configuration file for policies. If not provided, policies will be read from the metadata")
	flag.IntVar(&grpcPort, "port", lbac.ServerDefaultPort, "Port to listen on for gRPC requests")

}
