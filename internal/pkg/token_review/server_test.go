package tokenreview

import (
	"context"
	"errors"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

const (
	metaDataNamespace = "metadata_namespace"
)

type MockKubernetesClient struct {
	kubernetes.Interface
	response *authv1.TokenReview
}

func (m *MockKubernetesClient) AuthenticationV1() v1.AuthenticationV1Interface {
	return &MockTokenReviews{
		response: m.response,
	}
}

type MockTokenReviews struct {
	v1.AuthenticationV1Interface
	response *authv1.TokenReview
}

func (m *MockTokenReviews) TokenReviews() v1.TokenReviewInterface {
	return &MockTokenReviewInterface{
		response: m.response,
	}
}

type MockTokenReviewInterface struct {
	v1.TokenReviewInterface
	response *authv1.TokenReview
}

func (m *MockTokenReviewInterface) Create(ctx context.Context, tr *authv1.TokenReview, opts metav1.CreateOptions) (*authv1.TokenReview, error) {
	if m.response == nil {
		return nil, errors.New("mock error")
	}
	return m.response, nil
}

func validCheckRequest(path, token string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: path,
					Headers: map[string]string{
						"Authorization": "Bearer " + token,
					},
				},
			},
		},
	}
}

func TestCheck_AllowedPath(t *testing.T) {
	client := &MockKubernetesClient{}
	server := NewServer(Config{Paths: []string{"/allowed"}}, client)

	req := validCheckRequest("/not-allowed", "valid-token")
	resp, err := server.Check(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_OkResponse); !ok {
		t.Fatalf("expected OkResponse, got %T", resp.HttpResponse)
	}
}

func TestCheck_NoTokenInHeader(t *testing.T) {
	client := &MockKubernetesClient{}
	server := NewServer(Config{Paths: []string{"/allowed"}, ExtractTokenFromHeader: "Authorization"}, client)

	req := validCheckRequest("/allowed", "")
	resp, err := server.Check(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got one: %v", err)
	}

	if resp == nil {
		t.Fatalf("expected response, got nil")
	}

	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse); !ok {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
	if resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code != 401 {
		t.Fatalf("expected code 401, got %d", resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code)
	}
}

func TestCheck_TokenReviewFails(t *testing.T) {
	client := &MockKubernetesClient{}
	server := NewServer(Config{Paths: []string{"/allowed"}, ExtractTokenFromHeader: "Authorization"}, client)

	req := validCheckRequest("/allowed", "invalid-token")
	resp, err := server.Check(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got one: %v", err)
	}

	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse); !ok {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
	if resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code != 500 {
		t.Fatalf("expected code 500, got %d", resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code)
	}
}

func TestCheck_TokenNotAuthenticated(t *testing.T) {
	client := &MockKubernetesClient{
		response: &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: false,
			},
		},
	}
	server := NewServer(Config{Paths: []string{"/allowed"}, ExtractTokenFromHeader: "Authorization"}, client)

	req := validCheckRequest("/allowed", "invalid-token")
	resp, err := server.Check(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got one: %v", err)
	}

	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse); !ok {
		t.Fatalf("expected DeniedResponse, got %T", resp.HttpResponse)
	}
	if resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code != 403 {
		t.Fatalf("expected code 403, got %d", resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code)
	}
}

func TestCheck_Success(t *testing.T) {
	client := &MockKubernetesClient{
		response: &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "test-user",
					Groups:   []string{"test-group"},
					Extra: map[string]authv1.ExtraValue{
						"test-key": []string{"test-value"},
					},
				},
				Audiences: []string{"test-audience"},
			},
		},
	}
	server := NewServer(Config{Paths: []string{"/allowed"}, ExtractTokenFromHeader: defaultAuthHeader, MetaDataNamespace: metaDataNamespace}, client)
	req := validCheckRequest("/allowed", "valid-token")
	resp, err := server.Check(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_OkResponse); !ok {
		t.Fatalf("expected OkResponse, got %T", resp.HttpResponse)
	}

	if resp.DynamicMetadata == nil {
		t.Fatalf("expected metadata context, got nil")
	}

	if resp.DynamicMetadata.Fields == nil {
		t.Fatalf("expected metadata fields, got nil")
	}

	if resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["username"].GetStringValue() != "test-user" {
		t.Fatalf("expected username test-user, got %s", resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["username"].GetStringValue())
	}

	if resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["groups"].GetListValue().Values[0].GetStringValue() != "test-group" {
		t.Fatalf("expected group test-group, got %s", resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["groups"].GetListValue().Values[0].GetStringValue())
	}

	if resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["audiences"].GetListValue().Values[0].GetStringValue() != "test-audience" {
		t.Fatalf("expected audience test-audience, got %s", resp.DynamicMetadata.Fields[metaDataNamespace].GetStructValue().Fields["audiences"].GetListValue().Values[0].GetStringValue())
	}
}
