package envoy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/philipgough/prom-auth-proxy/pkg/lbac"
)

const (
	envoyImage = "envoyproxy/envoy"
	envoyTag   = "v1.30.6"

	httpbinName  = "httpbin.org"
	httpPort     = 80
	httpbinImage = "kennethreitz/httpbin"
	httpbinTag   = "latest"

	lbacName  = "lbac"
	lbacImage = "quay.io/philipgough/lbac"
	lbacTag   = "latest"
)

const (
	signal = "metrics"

	testReadPath  = "/anything"
	testWritePath = "/anything/else"

	caFileName = "ca.pem"
	serverCert = "server.pem"
	serverKey  = "server-key.pem"
	caFilePath = "/tmp/certs/" + caFileName
	certPath   = "/tmp/certs/" + serverCert
	keyPath    = "/tmp/certs/" + serverKey
)

var (
	pool    *dockertest.Pool
	network *dockertest.Network
)

func TestMain(m *testing.M) {
	var err error
	pool, err = dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not construct pool: %s", err)
	}

	err = pool.Client.Ping()
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	network, err = pool.CreateNetwork("test-network")
	if err != nil {
		log.Fatalf("could not create network: %v", err)
	}

	options := dockertest.RunOptions{
		Name:         httpbinName,
		Hostname:     httpbinName,
		Repository:   httpbinImage,
		Tag:          httpbinTag,
		ExposedPorts: []string{"80"},
		Networks: []*dockertest.Network{
			network,
		},
	}

	resource, err := pool.RunWithOptions(&options, hostConfig)
	if err != nil {
		log.Fatalf("could not start resource: %s", err)
	}

	err = pool.Retry(func() error {
		probe := fmt.Sprintf("http://localhost:%s/", resource.GetPort("80/tcp"))
		resp, err := http.DefaultClient.Get(probe)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("could not connect to httpbin: %s", err)
	}

	cleanup := func() {
		pool.Purge(resource)
		if err != nil {
			log.Fatalf("could not purge resource: %s", err)
		}
		network.Close()
	}

	defer cleanup()

	m.Run()
}

func TestOpts_Routing(t *testing.T) {
	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testReadPath,
			},
		},
		WriteOptions: &WriteBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testWritePath,
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	readPort := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	writePort := resource.GetPort(fmt.Sprintf("%d/tcp", WriteListenerPort))

	resp, err := http.Get(fmt.Sprintf("http://localhost:%s%s", readPort, testReadPath))
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	resp, err = http.Get(fmt.Sprintf("http://localhost:%s%s", writePort, testWritePath))
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	resp, err = http.Get(fmt.Sprintf("http://localhost:%s/anything/other", readPort))
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status code 404, got %d", resp.StatusCode)
	}
}

func TestOpts_HeaderManipulation(t *testing.T) {
	fromHeader := "X-Some-Test-Header"
	fromHeaderVal := "test"
	toHeader := "X-Thanos-Tenant"

	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testReadPath,
				HeaderMutations: []HeaderMutation{
					{
						SetHeader: toHeader,
						FromValue: ExistingHeaderMutation{
							FromRequestHeader: fromHeader,
						},
					},
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	readPort := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	url := fmt.Sprintf("http://localhost:%s%s", readPort, testReadPath)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}
	req.Header.Add(fromHeader, fromHeaderVal)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
	respBody := getAnythingResponseBody(t, resp.Body)
	if respBody.Headers[toHeader] != fromHeaderVal {
		t.Fatalf("expected header %s to be %s, got %s", toHeader, fromHeaderVal, respBody.Headers[toHeader])
	}
}

func TestOpts_HeaderAmendments(t *testing.T) {
	someHeaderToInitiallySend := "X-Some-Test-Header-To-Send"
	someHeaderToInitiallySendVal := "test-send"

	someHeaderToAddAtRouteMatch := "X-Some-Test-Header"
	someHeaderToAddAtRouteMatchVal := "test-add"

	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				HeaderAmendments: HeaderAmendments{
					AddHeaders: map[string]string{
						someHeaderToAddAtRouteMatch: someHeaderToAddAtRouteMatchVal,
					},
					RemoveHeaders: []string{someHeaderToInitiallySend},
				},
				MatchRouteRegex: testReadPath,
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	url := fmt.Sprintf("http://localhost:%s%s", port, testReadPath)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	req.Header.Add(someHeaderToInitiallySend, someHeaderToInitiallySendVal)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
	respBody := getAnythingResponseBody(t, resp.Body)
	_, ok := respBody.Headers[someHeaderToInitiallySend]
	if ok {
		t.Fatalf("expected header %s to be removed", someHeaderToInitiallySend)
	}

	if respBody.Headers[someHeaderToAddAtRouteMatch] != someHeaderToAddAtRouteMatchVal {
		t.Fatalf("expected header %s to be %s, got %s", someHeaderToAddAtRouteMatch, someHeaderToAddAtRouteMatchVal, respBody.Headers[someHeaderToAddAtRouteMatch])
	}
}

func TestOpts_HeaderMatching(t *testing.T) {
	fromHeader := "X-Some-Test-Header"
	fromHeaderVal := "test"

	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				HeaderMatcher: &HeaderMatcher{
					Name:  fromHeader,
					Regex: fromHeaderVal,
				},
				MatchRouteRegex: testReadPath,
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status code 404, got %d", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}
	req.Header.Add(fromHeader, fromHeaderVal)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
}

func TestOpts_TokenAuth_JWT(t *testing.T) {
	providerName := "istio_demo"
	jwtProvider := JWTProvider{
		Issuer: "testing@secure.istio.io",
		RemoteJWKsURI: RemoteJWKSURI{
			URI: "https://raw.githubusercontent.com/istio/istio/release-1.23/security/tools/jwt/samples/jwks.json",
		},
	}

	opts := Options{
		Signal: signal,
		TokenAuthConfig: &TokenAuthConfig{
			JWTProviders: map[string]JWTProvider{
				providerName: jwtProvider,
			},
		},
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				MatchRouteRegex: testReadPath,
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				TokenAuthConfig: BackendTokenAuthConfig{
					JWTAuth: &BackendJWTAuth{
						ProviderName: providerName,
					},
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code 401, got %d", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	token, err := os.ReadFile("testdata/demo.jwt")
	if err != nil {
		t.Fatalf("unable to read file: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", strings.TrimSpace(string(token))))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
}

func TestOpts_TokenAuth_JWT_RBAC(t *testing.T) {
	providerName := "istio_demo"
	jwtProvider := JWTProvider{
		Issuer: "testing@secure.istio.io",
		RemoteJWKsURI: RemoteJWKSURI{
			URI: "https://raw.githubusercontent.com/istio/istio/release-1.23/security/tools/jwt/samples/jwks.json",
		},
	}

	opts := Options{
		Signal: signal,
		TokenAuthConfig: &TokenAuthConfig{
			JWTProviders: map[string]JWTProvider{
				providerName: jwtProvider,
			},
		},
		ReadOptions: &ReadBackend{
			RBACPolicies: map[string]string{
				"some-test-policy": "'group1' in token.groups",
			},
			BackendOptions: BackendOptions{
				MatchRouteRegex: testReadPath,
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				TokenAuthConfig: BackendTokenAuthConfig{
					JWTAuth: &BackendJWTAuth{
						ProviderName: providerName,
					},
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code 401, got %d", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	// This token decodes as follows:
	// {
	//  "exp": 4685989700,
	//  "foo": "bar",
	//  "iat": 1532389700,
	//  "iss": "testing@secure.istio.io",
	//  "sub": "testing@secure.istio.io"
	// }

	token, err := os.ReadFile("testdata/demo.jwt")
	if err != nil {
		t.Fatalf("unable to read file: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", strings.TrimSpace(string(token))))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status code 403, got %d", resp.StatusCode)
	}
	req.Header.Del("Authorization")

	// This token decodes as follows:
	// {
	//  "exp": 3537391104,
	//  "groups": [
	//    "group1",
	//    "group2"
	//  ],
	//  "iat": 1537391104,
	//  "iss": "testing@secure.istio.io",
	//  "scope": [
	//    "scope1",
	//    "scope2"
	//  ],
	//  "sub": "testing@secure.istio.io"
	// }
	groupsToken, err := os.ReadFile("testdata/group-scopes.jwt")
	if err != nil {
		t.Fatalf("unable to read file: %v", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", strings.TrimSpace(string(groupsToken))))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
}

func TestOpts_MTLS(t *testing.T) {
	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testReadPath,
			},
		},
		WriteOptions: &WriteBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testWritePath,
				MTLSConfig: &MTLSConfig{
					TrustedCA:  caFilePath,
					ServerCert: certPath,
					ServerKey:  keyPath,
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	port = resource.GetPort(fmt.Sprintf("%d/tcp", WriteListenerPort))
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%s%s", port, testWritePath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, mtlsErr := http.DefaultClient.Do(req)
	if mtlsErr == nil {
		t.Fatalf("expected error, got none")
	}

	caCert, err := os.ReadFile("testdata/certs/ca.pem")
	if err != nil {
		t.Fatalf("could not read ca cert: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("testdata/certs/client.pem", "testdata/certs/client-key.pem")
	if err != nil {
		t.Fatalf("could not load client cert: %s", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	expectOkResp, expectNoErr := client.Do(req)
	if expectNoErr != nil {
		t.Fatalf("expected no error, got %s", expectNoErr)
	}

	if expectOkResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", expectOkResp.StatusCode)
	}
}

func TestOpts_MTLS_RBAC(t *testing.T) {
	opts := Options{
		Signal: signal,
		ReadOptions: &ReadBackend{
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testReadPath,
			},
		},
		WriteOptions: &WriteBackend{
			RBACPolicies: map[string]string{
				"some-test-policy": "!connection.subject_peer_certificate.contains('client')",
			},
			BackendOptions: BackendOptions{
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				MatchRouteRegex: testWritePath,
				MTLSConfig: &MTLSConfig{
					TrustedCA:  caFilePath,
					ServerCert: certPath,
					ServerKey:  keyPath,
				},
			},
		},
	}

	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", port, testReadPath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	port = resource.GetPort(fmt.Sprintf("%d/tcp", WriteListenerPort))
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%s%s", port, testWritePath), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	resp, mtlsErr := http.DefaultClient.Do(req)
	if mtlsErr == nil {
		t.Fatalf("expected error, got none")
	}

	caCert, err := os.ReadFile("testdata/certs/ca.pem")
	if err != nil {
		t.Fatalf("could not read ca cert: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("testdata/certs/client.pem", "testdata/certs/client-key.pem")
	if err != nil {
		t.Fatalf("could not load client cert: %s", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	response, expectErr := client.Do(req)
	if expectErr != nil {
		t.Fatalf("expected no error, got %s", expectErr)
	}

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status code 403, got %d", response.StatusCode)
	}

	secondCert, err := tls.LoadX509KeyPair("testdata/certs/second-client.pem", "testdata/certs/second-client-key.pem")
	if err != nil {
		t.Fatalf("could not load client cert: %s", err)
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{secondCert},
			},
		},
	}
	expectOkRep, expectNoErr := client.Do(req)
	if expectNoErr != nil {
		t.Fatalf("expected no error, got %s", expectNoErr)
	}

	if expectOkRep.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", expectOkRep.StatusCode)
	}
}

func TestOpts_LBAC_JWT(t *testing.T) {
	providerName := "istio_demo"
	match := "/anything/.*"
	policies := []lbac.RawPolicy{
		{
			Name:          "some-policy",
			CELExpression: "token.sub == 'testing@secure.istio.io'",
			Selectors: []lbac.RawSelector{
				{

					LabelSelector: `{app='test'}`,
				},
			},
		},
	}

	jwtProvider := JWTProvider{
		Issuer: "testing@secure.istio.io",
		RemoteJWKsURI: RemoteJWKSURI{
			URI: "https://raw.githubusercontent.com/istio/istio/release-1.23/security/tools/jwt/samples/jwks.json",
		},
	}

	opts := Options{
		Signal: signal,
		TokenAuthConfig: &TokenAuthConfig{
			JWTProviders: map[string]JWTProvider{
				providerName: jwtProvider,
			},
		},
		ReadOptions: &ReadBackend{
			LBACConfig: &LBACConfig{
				LBACServer: LBACServerConfig{
					Address:  lbacName,
					GrpcPort: 3001,
				},
				LBACPolicies: policies,
			},
			BackendOptions: BackendOptions{
				MatchRouteRegex: match,
				BackendConfig: Backend{
					Address: httpbinName,
					Port:    httpPort,
				},
				TokenAuthConfig: BackendTokenAuthConfig{
					JWTAuth: &BackendJWTAuth{
						ProviderName: providerName,
					},
				},
			},
		},
	}

	_ = runLBACServer(t)
	resource := runEnvoy(t, opts.BuildOrDie())

	readPort := resource.GetPort(fmt.Sprintf("%d/tcp", ReadListenerPort))
	path := "/anything/api/v1/query?query=up"
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s%s", readPort, path), nil)
	if err != nil {
		t.Fatalf("could not create request: %s", err)
	}

	// This token decodes as follows:
	// {
	//  "exp": 4685989700,
	//  "foo": "bar",
	//  "iat": 1532389700,
	//  "iss": "testing@secure.istio.io",
	//  "sub": "testing@secure.istio.io"
	// }

	token, err := os.ReadFile("testdata/demo.jwt")
	if err != nil {
		t.Fatalf("unable to read file: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", strings.TrimSpace(string(token))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("could not get response: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
	out := getAnythingResponseBody(t, resp.Body)
	if !strings.Contains(out.URL, `/anything/api/v1/query?query=up{app%3D"test"}`) {
		t.Fatalf("expected URL to contain label selector, got %s", out.URL)
	}
}

// runEnvoy starts an envoy container with the provided config and returns the resource
// it copies the certs from the testdata/certs directory to the temp directory and makes them
// available to the envoy container at /tmp/certs
func runEnvoy(t *testing.T, withConfig string) *dockertest.Resource {
	t.Helper()

	tempDir := t.TempDir()
	err := os.CopyFS(tempDir, os.DirFS("testdata/certs"))
	if err != nil {
		t.Fatalf("could not copy certs: %s", err)
	}

	dir := t.TempDir()
	err = os.WriteFile(dir+"/envoy.yaml", []byte(withConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("/tmp/envoy.yaml", []byte(withConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	exposedPorts := []string{
		fmt.Sprintf("%d", AdminPort),
		fmt.Sprintf("%d", ReadListenerPort),
		fmt.Sprintf("%d", WriteListenerPort),
	}

	options := dockertest.RunOptions{
		Repository:   envoyImage,
		Tag:          envoyTag,
		Cmd:          []string{"envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "debug"},
		ExposedPorts: exposedPorts,
		Mounts: []string{
			dir + "/envoy.yaml:/etc/envoy/envoy.yaml",
			tempDir + "/" + caFileName + ":" + caFilePath,
			tempDir + "/" + serverCert + ":" + certPath,
			tempDir + "/" + serverKey + ":" + keyPath,
		},
		Networks: []*dockertest.Network{
			network,
		},
	}

	resource, err := pool.RunWithOptions(&options, hostConfig)
	if err != nil {
		t.Fatalf("could not start resource: %s", err)
	}

	t.Cleanup(func() {
		err := pool.Purge(resource)
		if err != nil {
			t.Fatalf("could not purge resource: %s", err)
		}
	})

	err = pool.Retry(func() error {
		probe := fmt.Sprintf("http://localhost:%s/ready", resource.GetPort(fmt.Sprintf("%d/tcp", AdminPort)))
		resp, err := http.DefaultClient.Get(probe)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("could not connect to envoy: %s", err)
	}
	return resource
}

func runLBACServer(t *testing.T) *dockertest.Resource {
	t.Helper()

	options := dockertest.RunOptions{
		Name:       lbacName,
		Repository: lbacImage,
		Tag:        lbacTag,
		Networks: []*dockertest.Network{
			network,
		},
	}

	resource, err := pool.RunWithOptions(&options, hostConfig)
	if err != nil {
		t.Fatalf("could not start resource: %s", err)
	}

	t.Cleanup(func() {
		err := pool.Purge(resource)
		if err != nil {
			t.Fatalf("could not purge resource: %s", err)
		}
	})
	return resource
}

var hostConfig = func(config *docker.HostConfig) {
	config.AutoRemove = true
	config.RestartPolicy = docker.RestartPolicy{Name: "no"}
}

type anythingResponse struct {
	Args struct {
	} `json:"args"`
	Data  string `json:"data"`
	Files struct {
	} `json:"files"`
	Form struct {
	} `json:"form"`
	Headers map[string]string `json:"headers"`
	JSON    any               `json:"json"`
	Method  string            `json:"method"`
	Origin  string            `json:"origin"`
	URL     string            `json:"url"`
}

func getAnythingResponseBody(t *testing.T, closer io.ReadCloser) anythingResponse {
	t.Helper()
	var anyResp anythingResponse
	err := json.NewDecoder(closer).Decode(&anyResp)
	if err != nil {
		t.Fatalf("could not decode response: %s", err)
	}
	return anyResp
}
