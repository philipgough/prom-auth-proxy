package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	tokenreviewserver "github.com/philipgough/prom-auth-proxy/internal/pkg/token_review"
	tokenreview "github.com/philipgough/prom-auth-proxy/pkg/token_review"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	port int

	masterURL  string
	kubeconfig string

	extractTokenFromHeader string
	metadataNamespace      string
	tokenKey               string
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

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		log.Fatalf("error building kubeconfig: %s", err.Error())
	}

	c := &tokenreview.Config{
		ExtractTokenFromHeader: extractTokenFromHeader,
		MetaDataNamespace:      metadataNamespace,
		TokenKey:               tokenKey,
	}

	s := tokenreviewserver.NewServer(c, kubernetes.NewForConfigOrDie(cfg))

	endPoint := fmt.Sprintf(":%d", port)
	listen, err := net.Listen("tcp", endPoint)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}

	opts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	grpcServer := grpc.NewServer(opts...)

	authv3.RegisterAuthorizationServer(grpcServer, s)
	healthpb.RegisterHealthServer(grpcServer, &healthServer{})

	log.Print("Starting gRPC server")
	grpcServer.Serve(listen)
}

func init() {
	flag.IntVar(&port, "port", tokenreview.ServerDefaultPort, "The port to listen on")
	flag.StringVar(&metadataNamespace, "metadata-namespace", tokenreview.ServerName, "The namespace to write the metadata to")
	flag.StringVar(&tokenKey, "token-key", tokenreview.DefaultSubKey, "The key to use for the token in the metadata")
	flag.StringVar(&extractTokenFromHeader, "extract-token-from-header", tokenreview.DefaultAuthHeader, "The header to extract the token from")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.",
	)
}
