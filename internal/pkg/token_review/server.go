package tokenreview

import (
	"context"
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	tokenreview "github.com/philipgough/prom-auth-proxy/pkg/token_review"

	"google.golang.org/protobuf/types/known/structpb"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Server is the server that implements the AuthorizationServer interface.
// Server issues TokenReview requests to the Kubernetes API server for a set of requested paths.
type Server struct {
	config tokenreview.Config
	client kubernetes.Interface
}

// NewServer creates a new Server.
func NewServer(config *tokenreview.Config, client kubernetes.Interface) *Server {
	if config == nil {
		config = &tokenreview.Config{}
	}

	if config.ExtractTokenFromHeader == "" {
		config.ExtractTokenFromHeader = tokenreview.DefaultAuthHeader
	}
	if config.MetaDataNamespace == "" {
		config.MetaDataNamespace = tokenreview.DefaultMetadataNamespace
	}
	if config.TokenKey == "" {
		config.TokenKey = tokenreview.DefaultSubKey
	}

	return &Server{
		config: *config,
		client: client,
	}
}

// Check the request and return a response.
// If the TokenReview request is successful, the request is allowed and the UserInfo is set on the request metadata.
// If the TokenReview request is not successful, the request is denied.
func (s *Server) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	token, err := s.extractToken(request)
	if err != nil {
		return s.returnUnauthorized(typev3.StatusCode_Unauthorized, "Unauthorized")
	}

	tokenReviewResult, err := s.doTokenReview(ctx, token)
	if err != nil {
		return s.returnUnauthorized(typev3.StatusCode_InternalServerError, "Internal Server Error")
	}

	if !tokenReviewResult.Status.Authenticated {
		return s.returnUnauthorized(typev3.StatusCode_Forbidden, "Forbidden")
	}

	resp := s.authorized()
	if resp.DynamicMetadata == nil {
		resp.DynamicMetadata = &structpb.Struct{}
	}

	if resp.DynamicMetadata.Fields == nil {
		resp.DynamicMetadata.Fields = make(map[string]*structpb.Value)
	}

	resp.DynamicMetadata.Fields[s.config.MetaDataNamespace] = &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: tokenreview.StatusToValue(s.config.TokenKey, tokenReviewResult.Status),
			},
		},
	}

	return resp, nil
}

func (s *Server) extractToken(request *authv3.CheckRequest) (string, error) {
	if s.config.ExtractTokenFromHeader == "" {
		return "", fmt.Errorf("no header to extract token from")
	}

	header := strings.ToLower(s.config.ExtractTokenFromHeader)

	headers := request.Attributes.Request.GetHttp().GetHeaders()
	if headers == nil {
		return "", fmt.Errorf("no headers in request")
	}

	token, ok := headers[header]
	if !ok {
		return "", fmt.Errorf("no token in headers")
	}

	if strings.ToLower(header) == tokenreview.DefaultAuthHeader {
		// The token is expected to be in the format "Bearer <token>
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if token == "" {
		return "", fmt.Errorf("token is empty")
	}

	return token, nil
}

func (s *Server) authorized() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

func (s *Server) returnUnauthorized(code typev3.StatusCode, body string) (*authv3.CheckResponse, error) {
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: code,
				},
				Body: body,
			},
		},
	}, nil
}

func (s *Server) doTokenReview(ctx context.Context, token string) (*authv1.TokenReview, error) {
	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}
	return s.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
}
