package envoy

import (
	"fmt"
	"log"
	"net/http"
	"os"
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