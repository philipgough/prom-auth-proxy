package envoy

import (
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
)

const (
	envoyImage = "envoyproxy/envoy"
	envoyTag   = "v1.30.6"

	httpbinName  = "httpbin.org"
	httpPort     = 80
	httpbinImage = "kennethreitz/httpbin"
	httpbinTag   = "latest"
)

const (
	testReadPath  = "/anything"
	testWritePath = "/anything/else"
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
		MetricsReadOptions: &BackendOptions{
			BackendConfig: Backend{
				Address: httpbinName,
				Port:    httpPort,
			},
			MatchRouteRegex: testReadPath,
		},
		MetricsWriteOptions: &BackendOptions{
			BackendConfig: Backend{
				Address: httpbinName,
				Port:    httpPort,
			},
			MatchRouteRegex: testWritePath,
		},
	}
	resource := runEnvoy(t, opts.BuildOrDie())

	readPort := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
	writePort := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsWriteListenerPort))

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
		MetricsReadOptions: &BackendOptions{
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
	}
	resource := runEnvoy(t, opts.BuildOrDie())
	readPort := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
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
		MetricsReadOptions: &BackendOptions{
			HeaderAmendments: HeaderAmendments{
				AddHeaders: map[string]string{
					someHeaderToAddAtRouteMatch: someHeaderToAddAtRouteMatchVal,
				},
				RemoveHeaders: []string{someHeaderToInitiallySend},
			},
			MatchRouteRegex: testReadPath,
			BackendConfig: Backend{
				Address: httpbinName,
				Port:    httpPort,
			},
		},
	}
	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
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
		MetricsReadOptions: &BackendOptions{
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
	}
	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
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
		TokenAuthConfig: &TokenAuthConfig{
			JWTProviders: map[string]JWTProvider{
				providerName: jwtProvider,
			},
		},
		MetricsReadOptions: &BackendOptions{
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
	}
	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
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
		CELPolicies: CELPolicies{
			"some-test-policy": "'group1' in token.groups",
		},
		TokenAuthConfig: &TokenAuthConfig{
			JWTProviders: map[string]JWTProvider{
				providerName: jwtProvider,
			},
		},
		MetricsReadOptions: &BackendOptions{
			MatchRouteRegex: testReadPath,
			BackendConfig: Backend{
				Address: httpbinName,
				Port:    httpPort,
			},
			TokenAuthConfig: BackendTokenAuthConfig{
				JWTAuth: &BackendJWTAuth{
					ProviderName:          providerName,
					AllowNamedCELPolicies: []string{"some-test-policy"},
				},
			},
		},
	}
	resource := runEnvoy(t, opts.BuildOrDie())
	port := resource.GetPort(fmt.Sprintf("%d/tcp", MetricsReadListenerPort))
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

func runEnvoy(t *testing.T, withConfig string) *dockertest.Resource {
	t.Helper()
	dir := t.TempDir()
	err := os.WriteFile(dir+"/envoy.yaml", []byte(withConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("/tmp/envoy.yaml", []byte(withConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	exposedPorts := []string{
		fmt.Sprintf("%d", AdminPort),
		fmt.Sprintf("%d", MetricsReadListenerPort),
		fmt.Sprintf("%d", MetricsWriteListenerPort),
	}

	options := dockertest.RunOptions{
		Repository:   envoyImage,
		Tag:          envoyTag,
		Cmd:          []string{"envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "debug"},
		ExposedPorts: exposedPorts,
		Mounts: []string{
			dir + "/envoy.yaml:/etc/envoy/envoy.yaml",
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
