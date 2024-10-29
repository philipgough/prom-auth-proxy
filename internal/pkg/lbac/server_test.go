package lbac

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/philipgough/prom-auth-proxy/pkg/lbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	tokenMetadataKey = "token"
	nsMetadata       = "test"
)

// MockExternalProcessorServer is a mock implementation of the ExternalProcessor_ProcessServer interface.
type MockExternalProcessorServer struct {
	grpc.ServerStream
	RecvFunc func() (*extprocpb.ProcessingRequest, error)
	SendFunc func(*extprocpb.ProcessingResponse) error
	ctx      context.Context
}

func (m *MockExternalProcessorServer) Recv() (*extprocpb.ProcessingRequest, error) {
	return m.RecvFunc()
}

func (m *MockExternalProcessorServer) Send(resp *extprocpb.ProcessingResponse) error {
	return m.SendFunc(resp)
}

func (m *MockExternalProcessorServer) Context() context.Context {
	return m.ctx
}

func Test_Process_InvalidHTTPMethod(t *testing.T) {
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodPut)},
						{Key: ":path", RawValue: []byte("/query")},
					},
				},
			},
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			if _, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestHeaders); !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}

			if resp.ModeOverride.RequestBodyMode != extprocv3.ProcessingMode_NONE {
				t.Fatalf("expected RequestBodyMode to be NONE, got %v", resp.ModeOverride.RequestBodyMode)
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_InvalidPath(t *testing.T) {
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/other")},
					},
				},
			},
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			if _, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestHeaders); !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}

			if resp.ModeOverride.RequestBodyMode != extprocv3.ProcessingMode_NONE {
				t.Fatalf("expected RequestBodyMode to be NONE, got %v", resp.ModeOverride.RequestBodyMode)
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_InvalidGETQueryParams(t *testing.T) {
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/query")},
					},
				},
			},
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			if _, ok := resp.Response.(*extprocpb.ProcessingResponse_ImmediateResponse); !ok {
				t.Fatalf("expected immediate response on bad query got %T", resp.Response)
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidGETRequestNoPoliciesInMetadata(t *testing.T) {
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/query?query=up")},
					},
				},
			},
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			if _, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestHeaders); !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}
			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidGETRequestNoMatchingPolicyAppliedInvalidExpression(t *testing.T) {
	p := []byte(`
  - name: policy1
    expression: "token.method == 'GET'"
    selectors:
      - label_selector: "{foo='bar'}"
  - name: policy2
    expression: "token.method == 'GET'"
    selectors:
      - label_selector: "{foo='bar'}"
`)

	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/query?query=up")},
					},
				},
			},
		},
		MetadataContext: &corev3.Metadata{
			FilterMetadata: setupState(t, p),
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			r, ok := resp.Response.(*extprocpb.ProcessingResponse_ImmediateResponse)
			if !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}
			if r.ImmediateResponse.GrpcStatus.Status != uint32(codes.InvalidArgument) {
				t.Fatalf("expected status code %v, got %v", codes.InvalidArgument, r.ImmediateResponse.Status)
			}
			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidGETRequestNoMatchingPolicyApplied(t *testing.T) {
	p := []byte(`
  - name: policy1
    expression: "token.sub == 'GET'"
    selectors:
      - label_selector: "{foo='bar'}"
`)

	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/query?query=up")},
					},
				},
			},
		},
		MetadataContext: &corev3.Metadata{
			FilterMetadata: setupState(t, p),
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			r, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestHeaders)
			if !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}
			if len(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()) != 1 {
				t.Fatalf("expected 1 header, got %v", len(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()))
			}

			if r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetKey() != ":path" {
				t.Fatalf("expected :path header, got %v", r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetKey())
			}
			if string(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetRawValue()) != "/query?query=up" {
				t.Fatalf("expected /query?query=up header value, got %v", string(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetRawValue()))
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidGETRequestMatchingPolicyApplied(t *testing.T) {
	p := []byte(`
  - name: policy1
    expression: "token.sub == 'testing@secure.istio.io'"
    selectors:
      - label_selector: "{foo='bar'}"
`)

	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocpb.HttpHeaders{
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", RawValue: []byte(http.MethodGet)},
						{Key: ":path", RawValue: []byte("/query?query=up")},
					},
				},
			},
		},
		MetadataContext: &corev3.Metadata{
			FilterMetadata: setupState(t, p),
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			r, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestHeaders)
			if !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}
			if len(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()) != 1 {
				t.Fatalf("expected 1 header, got %v", len(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()))
			}

			if r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetKey() != ":path" {
				t.Fatalf("expected :path header, got %v", r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetKey())
			}
			if string(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetRawValue()) != "/query?query=up%7Bfoo%3D%22bar%22%7D" {
				t.Fatalf("expected /query?query=up header value, got %v", string(r.RequestHeaders.GetResponse().GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetRawValue()))
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func getToken(t *testing.T) *structpb.Value {
	t.Helper()
	token := []byte(`
	{
	 "exp": 3537391104,
	 "groups": [
	   "group1",
	   "group2"
	 ],
	 "iat": 1537391104,
	 "iss": "testing@secure.istio.io",
	 "scope": [
	   "scope1",
	   "scope2"
	 ],
	 "sub": "testing@secure.istio.io"
	}
`)
	var to map[string]any
	err := json.Unmarshal(token, &to)
	if err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	v, err := structpb.NewValue(to)
	if err != nil {
		t.Fatalf("failed to create token struct: %v", err)
	}
	return v
}

func setupState(t *testing.T, withPolicies []byte) map[string]*structpb.Struct {
	t.Helper()

	withPoliciesValue, err := lbac.RawPolicyToFilterMetadata(withPolicies)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token := getToken(t)

	state := &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					lbac.DefaultStateKey: {
						Kind: &structpb.Value_StringValue{
							StringValue: tokenMetadataKey,
						},
					},
					lbac.DefaultStateNamespace: {
						Kind: &structpb.Value_StringValue{
							StringValue: nsMetadata,
						},
					},
				},
			},
		},
	}
	return map[string]*structpb.Struct{
		lbac.DefaultMetadataNamespace: {
			Fields: map[string]*structpb.Value{
				lbac.DefaultPolicySubKey: withPoliciesValue,
				lbac.DefaultStateSubKey:  state,
			},
		},
		nsMetadata: {
			Fields: map[string]*structpb.Value{
				tokenMetadataKey: token,
			},
		},
	}
}

func Test_Process_InvalidPOSTQuery(t *testing.T) {
	query := []byte(`{"queryzz": "up"}`)

	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestBody{
			RequestBody: &extprocpb.HttpBody{
				Body:        query,
				EndOfStream: true,
			},
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			if _, ok := resp.Response.(*extprocpb.ProcessingResponse_ImmediateResponse); !ok {
				t.Fatalf("expected immediate response on bad query got %T", resp.Response)
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidPOSTRequestNoMatchingPolicyApplied(t *testing.T) {
	p := []byte(`
  - name: policy1
    expression: "token.sub == 'GET'"
    selectors:
      - label_selector: "{foo='bar'}"
`)

	data := url.Values{}
	data.Set("query", "up")
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestBody{
			RequestBody: &extprocpb.HttpBody{
				Body:        []byte(data.Encode()),
				EndOfStream: true,
			},
		},
		MetadataContext: &corev3.Metadata{
			FilterMetadata: setupState(t, p),
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			r, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestBody)
			if !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}

			if string(r.RequestBody.GetResponse().GetBodyMutation().GetBody()) != data.Encode() {
				t.Fatalf("expected %v, got %v", data.Encode(), string(r.RequestBody.GetResponse().GetBodyMutation().GetBody()))
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}

func Test_Process_ValidPOSTRequestMatchingPolicyApplied(t *testing.T) {
	p := []byte(`
  - name: policy1
    expression: "token.sub == 'testing@secure.istio.io'"
    selectors:
      - label_selector: "{foo='bar'}"
`)

	data := url.Values{}
	data.Set("query", "up")
	req := &extprocpb.ProcessingRequest{
		Request: &extprocpb.ProcessingRequest_RequestBody{
			RequestBody: &extprocpb.HttpBody{
				Body:        []byte(data.Encode()),
				EndOfStream: true,
			},
		},
		MetadataContext: &corev3.Metadata{
			FilterMetadata: setupState(t, p),
		},
	}

	ctx, c := context.WithCancel(context.Background())
	mockSrv := &MockExternalProcessorServer{
		RecvFunc: func() (*extprocpb.ProcessingRequest, error) {
			return req, nil
		},
		SendFunc: func(resp *extprocpb.ProcessingResponse) error {
			if resp == nil {
				t.Fatalf("expected response, got nil")
			}
			r, ok := resp.Response.(*extprocpb.ProcessingResponse_RequestBody)
			if !ok {
				t.Fatalf("expected RequestHeaders response, got %T", resp.Response)
			}
			expect := url.Values{}
			expect.Set("query", `up{foo="bar"}`)
			if string(r.RequestBody.GetResponse().GetBodyMutation().GetBody()) != expect.Encode() {
				t.Fatalf("expected %v, got %v", expect.Encode(), string(r.RequestBody.GetResponse().GetBodyMutation().GetBody()))
			}

			c()
			return nil
		},
	}
	mockSrv.ctx = ctx

	srv := NewServer(nil)
	err := srv.Process(mockSrv)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected no error, got %v", err)
	}
}
