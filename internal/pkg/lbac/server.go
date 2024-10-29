package lbac

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/philipgough/prom-auth-proxy/pkg/lbac"
	"github.com/prometheus/prometheus/promql/parser"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// Server is an implementation of the ExternalProcessor gRPC service.
// See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter
// Server will check the provided metadata for the policies to enforce if not set explicitly.
// Server requires some runtime state to evaluate the lbac.Policies against.
// Metadata is checked under the lbac.DefaultMetadataNamespace key and the lbac.DefaultPolicySubKey sub-key.
// The server will expect the state to be passed in the metadata under the lbac.DefaultStateMetadataNamespace key and the lbac.DefaultStateSubKey sub-key.
// Under the state key, the server expects a struct with the following fields:
// - lbac.DefaultStateKey
// - lbac.
// This will be used as a reverse lookup to get the state from the metadata.
// Server
type Server struct {
	// policies is a list of policies to enforce.
	policies lbac.Policies
}

// ServerConfig is the configuration for the server.
type ServerConfig struct {
	// Policies is a list of policies to enforce.
	// If not set, the server will expect the policies to be passed in the metadata.
	Policies lbac.Policies
}

type FromMetadata struct {
	FromNamespace string
	FromKey       string
}

// NewServer creates a new Server.
// It can be passed a list of policies to enforce.
// If no policies are passed, the server will expect the policies to be passed in the metadata.
func NewServer(policies lbac.Policies) *Server {
	return &Server{policies: policies}
}

// Process is the main processing loop for the server.
func (s *Server) Process(srv extprocpb.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
		}

		resp := &extprocpb.ProcessingResponse{}
		switch v := req.Request.(type) {
		case *extprocpb.ProcessingRequest_RequestHeaders:
			h := req.Request.(*extprocpb.ProcessingRequest_RequestHeaders)
			method := getMethod(h)
			path := getPath(h)

			if !isValidRequest(method, path) {
				resp = &extprocpb.ProcessingResponse{Response: &extprocpb.ProcessingResponse_RequestHeaders{}, ModeOverride: skipFurtherProcessing()}
				break
			}

			u, err := parseURL(path)
			if err != nil {
				log.Printf("error parsing path: %v", err)
				resp = terminateProcessing(uint32(codes.InvalidArgument))
				break
			}

			if u.Query().Get(queryKey) == "" {
				// if it's a query but doesn't have the query key, skip further processing for GET requests
				if method == http.MethodGet {
					resp = terminateProcessing(uint32(codes.InvalidArgument))
					break
				}
				// otherwise continue on to applyLBACPolicies the request body
				resp = &extprocpb.ProcessingResponse{Response: &extprocpb.ProcessingResponse_RequestHeaders{}}
				break
			}

			injectedValues, err := s.applyLBACPolicies(req, u.Query())
			if err != nil {
				log.Printf("error applying policies: %v", err)
				resp = terminateProcessing(uint32(codes.InvalidArgument))
				break
			}

			path = fmt.Sprintf("%s?%s", u.Path, injectedValues.Encode())
			var override *extprocv3.ProcessingMode
			if method == http.MethodGet {
				override = skipFurtherProcessing()
			}

			resp = &extprocpb.ProcessingResponse{
				Response: &extprocpb.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extprocpb.HeadersResponse{
						Response: &extprocpb.CommonResponse{
							HeaderMutation: &extprocpb.HeaderMutation{
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header: &corev3.HeaderValue{
											Key:      ":path",
											RawValue: []byte(path),
										},
									},
								},
							},
						},
					},
				},
				ModeOverride: override,
			}
			break

		case *extprocpb.ProcessingRequest_RequestBody:
			r := req.Request
			b := r.(*extprocpb.ProcessingRequest_RequestBody)
			formValues, err := url.ParseQuery(string(b.RequestBody.GetBody()))
			if err != nil {
				log.Printf("error parsing form values: %v", err)
				resp = terminateProcessing(uint32(codes.InvalidArgument))
				break
			}

			if formValues.Get(queryKey) == "" {
				resp = terminateProcessing(uint32(codes.InvalidArgument))
				break
			}

			values, err := s.applyLBACPolicies(req, formValues)
			if err != nil {
				resp = terminateProcessing(uint32(codes.InvalidArgument))
				break
			}

			if b.RequestBody.EndOfStream {
				resp = &extprocpb.ProcessingResponse{
					Response: &extprocpb.ProcessingResponse_RequestBody{
						RequestBody: &extprocpb.BodyResponse{
							Response: &extprocpb.CommonResponse{
								HeaderMutation: &extprocpb.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header: &corev3.HeaderValue{
												Key:   "Content-Type",
												Value: "application/x-www-form-urlencoded",
											},
										},
									},
								},
								BodyMutation: &extprocpb.BodyMutation{
									Mutation: &extprocpb.BodyMutation_Body{
										Body: []byte(values.Encode()),
									},
								},
							},
						},
					},
				}
			}
			break
		default:
			log.Printf("Unknown Request type %v\n", v)

		}
		if err := srv.Send(resp); err != nil {
			log.Printf("send error %v", err)
		}
	}
}

// applyLBACPolicies to the values.
func (s *Server) applyLBACPolicies(req *extprocpb.ProcessingRequest, values url.Values) (url.Values, error) {
	var expr parser.Expr
	var err error

	policies := s.getPolicies(req)
	state := getStateFromMetadata(req)

	var policiesToEnforce lbac.Policies
	for _, policy := range policies {
		ok, err := policy.Evaluate(state)
		if err != nil {
			return nil, err
		}
		if ok {
			policiesToEnforce = append(policiesToEnforce, policy)
		}
	}

	expr, err = parser.ParseExpr(values.Get(queryKey))
	if err != nil {
		return nil, err
	}

	for _, policy := range policiesToEnforce {
		if err := policy.Apply(expr); err != nil {
			log.Printf("error applying policy: %v", err)
			return nil, err
		}
	}
	values.Set(queryKey, expr.String())
	return values, nil
}

func (s *Server) getPolicies(from *extprocpb.ProcessingRequest) lbac.Policies {
	if s.policies != nil {
		return s.policies
	}
	policies := getPolicyFromMetadata(from)
	if policies == nil {
		log.Printf("no policies found in metadata")
		return nil
	}

	b, err := policies.MarshalJSON()
	if err != nil {
		panic(err)
	}
	p, err := lbac.RawPolicyToPolicy(b)
	if err != nil {
		panic(err)
	}
	s.policies = p
	return s.policies
}

const queryKey = "query"

func parseURL(fromPath string) (*url.URL, error) {
	u, err := url.Parse(fromPath)
	if err != nil {
		return nil, err

	}
	return u, nil
}

func getPolicyFromMetadata(from *extprocpb.ProcessingRequest) *structpb.Value {
	md := getMetaData(from)
	if md == nil {
		return nil
	}

	check := md.FilterMetadata[lbac.DefaultMetadataNamespace].GetFields()
	if check == nil {
		return nil
	}
	return check[lbac.DefaultPolicySubKey]
}

func getStateFromMetadata(from *extprocpb.ProcessingRequest) map[string]any {
	stateMD := getMetaData(from)
	if stateMD == nil {
		return nil
	}
	check := stateMD.FilterMetadata[lbac.DefaultMetadataNamespace].GetFields()[lbac.DefaultStateSubKey]
	if check == nil {
		return nil
	}

	lookupNS := check.GetStructValue().GetFields()[lbac.DefaultStateNamespace].GetStringValue()
	return getMetaData(from).FilterMetadata[lookupNS].AsMap()
}

func getMetaData(from *extprocpb.ProcessingRequest) *corev3.Metadata {
	return from.GetMetadataContext()
}

func getMethod(from *extprocpb.ProcessingRequest_RequestHeaders) string {
	from.RequestHeaders.GetHeaders().GetHeaders()
	value, _ := getHeaderValue(from.RequestHeaders.GetHeaders().GetHeaders(), ":method")
	return value
}

func getPath(from *extprocpb.ProcessingRequest_RequestHeaders) string {
	value, _ := getHeaderValue(from.RequestHeaders.GetHeaders().GetHeaders(), ":path")
	return value
}

func getHeaderValue(headers []*corev3.HeaderValue, key string) (string, bool) {
	var result []byte
	ok := false
	for _, headerValue := range headers {
		if headerValue.Key == key {
			result = headerValue.RawValue
			ok = true
			break
		}
	}
	return string(result), ok
}

func terminateProcessing(withCode uint32) *extprocpb.ProcessingResponse {
	return &extprocpb.ProcessingResponse{
		Response: &extprocpb.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocpb.ImmediateResponse{
				GrpcStatus: &extprocpb.GrpcStatus{
					Status: withCode,
				},
			},
		},
		ModeOverride: skipFurtherProcessing(),
	}
}

func skipFurtherProcessing() *extprocv3.ProcessingMode {
	return &extprocv3.ProcessingMode{
		RequestBodyMode:    extprocv3.ProcessingMode_NONE,
		ResponseHeaderMode: extprocv3.ProcessingMode_SKIP,
		ResponseBodyMode:   extprocv3.ProcessingMode_NONE,
	}
}

func isValidRequest(method, path string) bool {
	if method != http.MethodGet && method != http.MethodPost {
		return false
	}
	if !strings.Contains(path, "/query") {
		return false
	}
	return true
}
