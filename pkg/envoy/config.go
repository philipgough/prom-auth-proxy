package envoy

import (
	"fmt"
	"net/url"
	"strings"

	envoyconfigbootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoyconfigclusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoymutationrulesv3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	envoyconfigcorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoylistenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoyroutev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoyheadermutationv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	envoyjwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	envoyrbacv3filter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	envoyrouterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoyconfigmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoymatcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"

	"github.com/ghodss/yaml"
	pbduration "github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"

	v1alpha1 "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	metricsReadClusterName  = "metrics_read"
	metricsWriteClusterName = "metrics_write"

	envoyListenerAddress = "0.0.0.0"
	AdminPort            = 9901

	metricsReadListenerName = "metrics_read_http_listener"
	MetricsReadListenerPort = 8080
	metricsReadStatsPrefix  = "metrics_read_http"

	envoyWriteListenerName   = "metrics_write_http_listener"
	MetricsWriteListenerPort = 8081
	metricsWriteStatsPrefix  = "metrics_write_http"

	tokenMetadataKey       = "token"
	tokenInMetadataPathJWT = "metadata.filter_metadata['envoy.filters.http.jwt_authn'].token."
)

// Backend represents a backend service that the proxy will route traffic to.
type Backend struct {
	// Address is the address of the backend service.
	Address string
	// Port is the port of the backend service.
	Port uint32
	// Scheme is the scheme of the backend service.
	// If empty, the scheme will be http.
	Scheme string
}

// BackendOptions is the configuration for the backend service.
type BackendOptions struct {
	// BackendConfig is the configuration for the backend service.
	BackendConfig Backend
	// MatchRouteRegex is the regex that the backend service will match on.
	MatchRouteRegex string
	// HeaderMutations is the mutations to be applied to HTTP headers.
	// These mutations will be applied to the incoming HTTP request before it is matched with a route.
	HeaderMutations HeaderMutations
	// HeaderAmendments allows the addition and removal of headers after a route is matched but before the request is sent to the backend.
	HeaderAmendments HeaderAmendments
	// HeaderMatcher is the header matcher that matches a header name and value.
	HeaderMatcher *HeaderMatcher
	// TokenAuthConfig is the configuration for token authentication.
	TokenAuthConfig BackendTokenAuthConfig
	// MTLSConfig is the configuration for mTLS.
	MTLSConfig *MTLSConfig
	// NamedCELRBACPolicies is the list of named CEL expressions for RBAC.
	// If not specified, the RBAC will not be checked.
	// If any of the expressions evaluate to true, the request will be allowed.
	// If all the expressions evaluate to false, the request will be denied.
	NamedCELRBACPolicies []string
	clusterName          string
	statsPrefix          string
	listenerName         string
	listenerPort         uint32
	attachedRBACPolicies CELPolicies
}

// HeaderMutation represents a mutation to be applied to HTTP headers.
// It contains the header to be set and the value to set it to.
type HeaderMutation struct {
	// SetHeader is the name of the header to be set.
	SetHeader string
	// FromValue is the value to set the header to, implementing the fmt.Stringer interface.
	FromValue fmt.Stringer
}

type HeaderMutations []HeaderMutation

// ExistingHeaderMutation represents a mutation that extracts a value from an existing HTTP request header.
// It contains the name of the header to look for in the incoming HTTP request.
type ExistingHeaderMutation struct {
	// FromRequestHeader specifies the header to look for in the incoming HTTP request.
	FromRequestHeader string
}

// String returns the string representation of the ExistingHeaderMutation.
func (ehm ExistingHeaderMutation) String() string {
	return fmt.Sprintf(`%%REQ(%s)%%`, ehm.FromRequestHeader)
}

// HeaderAmendments allows the addition and removal of headers after a route is
// matched but before the request is sent to the backend.
type HeaderAmendments struct {
	// AddHeaders is a map of headers to add to the request.
	AddHeaders map[string]string
	// RemoveHeaders is a list of headers to remove from the request.
	RemoveHeaders []string
}

// HeaderMatcher represents a header matcher that matches a header name and value.
// This can be used to enforce that a header is present and has a specific value.
type HeaderMatcher struct {
	Name  string
	Regex string
}

// JWTProvider defines the JWT provider configuration.
type JWTProvider struct {
	// Issuer URI of the JWT provider.
	Issuer string
	// RemoteJWKsURI is the URI of the JWKs endpoint
	RemoteJWKsURI RemoteJWKSURI
	// LocalJWK is the local JWKs.
	// If provided it is preferred over RemoteJWKsURI.
	LocalJWKs *string
}

// RemoteJWKSURI is the configuration for the remote JWKs URI.
type RemoteJWKSURI struct {
	// URI is the URI of the remote JWKs endpoint.
	URI string
	// Port is the port of the remote JWKs URI.
	// If not specified, the default port of 443 will be used.
	Port uint32
}

// JWTProviders is a map of JWT provider names to JWT providers.
type JWTProviders map[string]JWTProvider

// TokenAuthConfig is the configuration for token authentication.
type TokenAuthConfig struct {
	JWTProviders JWTProviders
}

// BackendTokenAuthConfig is the per-backend configuration for token authentication.
type BackendTokenAuthConfig struct {
	// JWTAuth is the JWT authentication configuration.
	// If not specified, the JWT authentication will not be enabled.
	JWTAuth *BackendJWTAuth
}

// CELPolicies is the map of named CEL policies to CEL expressions.
type CELPolicies map[string]string

// BackendJWTAuth is the per-backend configuration for JWT authentication.
type BackendJWTAuth struct {
	// ProviderName is the name of the JWT provider.
	ProviderName string
	// Audiences of the JWT provider.
	// If not specified, the audiences in JWT will not be checked.
	Audiences []string
	provider  JWTProvider
}

// MTLSConfig is the configuration for mTLS.
type MTLSConfig struct {
	// TrustedCA is the path to the trusted CA certificate.
	TrustedCA string
	// ServerCert is the path to the server certificate.
	ServerCert string
	// ServerKey is the path to the server key.
	ServerKey string
	// MatchSANs is the list of SANs to match.
	// If not specified, the SANs in the server certificate will not be checked.
	MatchSANs []string
}

// Options is the configuration for the gateway.
type Options struct {
	MetricsReadOptions  *BackendOptions
	MetricsWriteOptions *BackendOptions
	TokenAuthConfig     *TokenAuthConfig
	CELPolicies         CELPolicies
}

// BuildOrDie returns raw YAML configuration for envoy proxy or panics if it fails.
func (opts Options) BuildOrDie() string {
	var listenerConfigs []*envoylistenerv3.Listener

	if opts.TokenAuthConfig != nil {
		if opts.TokenAuthConfig.JWTProviders != nil {
			for _, backend := range []*BackendOptions{opts.MetricsReadOptions, opts.MetricsWriteOptions} {
				if backend != nil && backend.TokenAuthConfig.JWTAuth != nil {
					namedJWTProvider := backend.TokenAuthConfig.JWTAuth.ProviderName
					if jwtProvider, ok := opts.TokenAuthConfig.JWTProviders[namedJWTProvider]; !ok {
						panic(fmt.Errorf("JWT provider %s not found in token auth config", namedJWTProvider))
					} else {
						backend.TokenAuthConfig.JWTAuth.provider = jwtProvider
					}
				}
			}
		}
	}

	attachRBACPoliciesOrDie := func(backendOptions *BackendOptions) {
		if len(backendOptions.NamedCELRBACPolicies) > 0 {
			backendOptions.attachedRBACPolicies = make(map[string]string, len(backendOptions.NamedCELRBACPolicies))
			for _, policy := range backendOptions.NamedCELRBACPolicies {
				if expr, ok := opts.CELPolicies[policy]; !ok {
					panic(fmt.Errorf("CEL policy %s not found in CEL policies", policy))
				} else {
					backendOptions.attachedRBACPolicies[policy] = expr
				}
			}
		}
	}

	if opts.MetricsReadOptions != nil {
		opts.MetricsReadOptions.clusterName = metricsReadClusterName
		opts.MetricsReadOptions.listenerName = metricsReadListenerName
		opts.MetricsReadOptions.listenerPort = MetricsReadListenerPort
		opts.MetricsReadOptions.statsPrefix = metricsReadStatsPrefix
		attachRBACPoliciesOrDie(opts.MetricsReadOptions)
		listenerConfigs = append(listenerConfigs, buildListenerConfig(*opts.MetricsReadOptions))
	}

	if opts.MetricsWriteOptions != nil {
		opts.MetricsWriteOptions.clusterName = metricsWriteClusterName
		opts.MetricsWriteOptions.listenerName = envoyWriteListenerName
		opts.MetricsWriteOptions.listenerPort = MetricsWriteListenerPort
		opts.MetricsWriteOptions.statsPrefix = metricsWriteStatsPrefix
		attachRBACPoliciesOrDie(opts.MetricsWriteOptions)
		listenerConfigs = append(listenerConfigs, buildListenerConfig(*opts.MetricsWriteOptions))
	}

	bootstrap := &envoyconfigbootstrapv3.Bootstrap{
		Admin: buildEnvoyAdminConfig(),
		StaticResources: &envoyconfigbootstrapv3.Bootstrap_StaticResources{
			Listeners: listenerConfigs,
			Clusters:  opts.toClusters(),
		},
	}

	marshalOpts := protojson.MarshalOptions{Indent: "  "}
	b, err := marshalOpts.Marshal(bootstrap)
	if err != nil {
		panic(err)

	}
	y, err := yaml.JSONToYAML(b)
	if err != nil {
		panic(err)
	}

	return string(y)
}

func buildListenerConfig(opts BackendOptions) *envoylistenerv3.Listener {
	var httpFilters []*envoyconfigmanagerv3.HttpFilter
	if len(opts.HeaderMutations) > 0 {
		httpFilters = append(httpFilters, opts.HeaderMutations.toHttpFilter())
	}

	if opts.TokenAuthConfig.JWTAuth != nil {
		httpFilters = append(httpFilters, opts.TokenAuthConfig.JWTAuth.toHttpFilter(opts.MatchRouteRegex))
	}

	if len(opts.attachedRBACPolicies) > 0 {
		httpFilters = append(httpFilters, opts.attachedRBACPolicies.toHttpFilter())
	}

	connManager := buildHTTPConnectionManager(opts, httpFilters)
	pbCM, err := anypb.New(connManager)
	if err != nil {
		panic(err)
	}

	filterChains := []*envoylistenerv3.FilterChain{
		{
			Filters: []*envoylistenerv3.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoylistenerv3.Filter_TypedConfig{
						TypedConfig: pbCM,
					},
				},
			},
		},
	}

	if opts.MTLSConfig != nil {
		filterChains[0].TransportSocket = opts.MTLSConfig.toTransportSocket()
	}

	listener, err := buildEnvoyListener(opts.listenerName, opts.listenerPort, filterChains)
	if err != nil {
		panic(err)
	}

	return listener
}

// buildEnvoyListener returns the envoy listener for the gateway.
func buildEnvoyListener(listenerName string, listenerPort uint32, filterChains []*envoylistenerv3.FilterChain) (*envoylistenerv3.Listener, error) {
	listener := &envoylistenerv3.Listener{
		Name: listenerName,
		Address: &envoyconfigcorev3.Address{
			Address: &envoyconfigcorev3.Address_SocketAddress{
				SocketAddress: &envoyconfigcorev3.SocketAddress{
					Address: envoyListenerAddress,
					PortSpecifier: &envoyconfigcorev3.SocketAddress_PortValue{
						PortValue: listenerPort,
					},
				},
			},
		},
		FilterChains: filterChains,
	}
	return listener, nil
}

// buildHTTPConnectionManager returns the HTTP connection manager for the gateway.
func buildHTTPConnectionManager(opts BackendOptions, httpFilters []*envoyconfigmanagerv3.HttpFilter) *envoyconfigmanagerv3.HttpConnectionManager {
	routerConfig, err := anypb.New(&envoyrouterv3.Router{})
	if err != nil {
		panic(err)
	}

	httpFilters = append(httpFilters, &envoyconfigmanagerv3.HttpFilter{
		Name:       "envoy.filters.http.router",
		ConfigType: &envoyconfigmanagerv3.HttpFilter_TypedConfig{TypedConfig: routerConfig},
	})

	routes := []*envoyroutev3.Route{opts.toRoute()}

	return &envoyconfigmanagerv3.HttpConnectionManager{
		CodecType:  envoyconfigmanagerv3.HttpConnectionManager_AUTO,
		StatPrefix: opts.statsPrefix,

		RouteSpecifier: &envoyconfigmanagerv3.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoyroutev3.RouteConfiguration{
				Name: "service",
				VirtualHosts: []*envoyroutev3.VirtualHost{
					{
						Name:    "service",
						Domains: []string{"*"},
						Routes:  routes,
					},
				},
			},
		},
		HttpFilters: httpFilters,
	}
}

func (opts Options) toClusters() []*envoyconfigclusterv3.Cluster {
	var clusters []*envoyconfigclusterv3.Cluster
	if opts.MetricsReadOptions != nil {
		clusters = append(clusters, opts.MetricsReadOptions.BackendConfig.toCluster(metricsReadClusterName))
	}

	if opts.MetricsWriteOptions != nil {
		clusters = append(clusters, opts.MetricsWriteOptions.BackendConfig.toCluster(metricsWriteClusterName))
	}

	if opts.TokenAuthConfig != nil && len(opts.TokenAuthConfig.JWTProviders) > 0 {
		clusters = append(clusters, opts.TokenAuthConfig.JWTProviders.toClusters()...)
	}

	return clusters
}

// toCluster returns the envoy cluster for the backend.
func (b Backend) toCluster(name string) *envoyconfigclusterv3.Cluster {
	if b.Scheme == "" {
		b.Scheme = "http"
	}
	return buildEnvoyCluster(name, b.Scheme, b.Address, b.Port, envoyconfigclusterv3.Cluster_LOGICAL_DNS)
}

// buildEnvoyCluster returns the envoy cluster for the backend.
func buildEnvoyCluster(name string, scheme, address string, port uint32, discovery envoyconfigclusterv3.Cluster_DiscoveryType) *envoyconfigclusterv3.Cluster {
	cluster := &envoyconfigclusterv3.Cluster{
		Name:                 name,
		DnsLookupFamily:      envoyconfigclusterv3.Cluster_V4_ONLY,
		ClusterDiscoveryType: &envoyconfigclusterv3.Cluster_Type{Type: discovery},
		LoadAssignment: &envoyendpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoyendpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoyendpointv3.LbEndpoint{
						{
							HostIdentifier: &envoyendpointv3.LbEndpoint_Endpoint{
								Endpoint: &envoyendpointv3.Endpoint{
									Address: &envoyconfigcorev3.Address{
										Address: &envoyconfigcorev3.Address_SocketAddress{
											SocketAddress: &envoyconfigcorev3.SocketAddress{
												Address: address,
												PortSpecifier: &envoyconfigcorev3.SocketAddress_PortValue{
													PortValue: port,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if scheme == "https" {
		cluster.TransportSocket = &envoyconfigcorev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoyconfigcorev3.TransportSocket_TypedConfig{
				TypedConfig: &anypb.Any{
					TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				},
			},
		}
	}
	return cluster
}

// toRoute returns the envoy route for the backend.
func (b BackendOptions) toRoute() *envoyroutev3.Route {
	var requestHeaderToAdd []*envoyconfigcorev3.HeaderValueOption
	for header, value := range b.HeaderAmendments.AddHeaders {
		requestHeaderToAdd = append(requestHeaderToAdd, &envoyconfigcorev3.HeaderValueOption{
			Header: &envoyconfigcorev3.HeaderValue{
				Key:   header,
				Value: value,
			},
			AppendAction: envoyconfigcorev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	var headerMatch []*envoyroutev3.HeaderMatcher
	if b.HeaderMatcher != nil {
		headerMatch = []*envoyroutev3.HeaderMatcher{
			{
				Name: b.HeaderMatcher.Name,
				HeaderMatchSpecifier: &envoyroutev3.HeaderMatcher_StringMatch{
					StringMatch: &envoymatcher.StringMatcher{
						MatchPattern: &envoymatcher.StringMatcher_SafeRegex{
							SafeRegex: &envoymatcher.RegexMatcher{
								Regex: b.HeaderMatcher.Regex,
							},
						},
					},
				},
			},
		}
	}

	return &envoyroutev3.Route{
		Match: &envoyroutev3.RouteMatch{
			Headers: headerMatch,
			PathSpecifier: &envoyroutev3.RouteMatch_SafeRegex{
				SafeRegex: &envoymatcher.RegexMatcher{
					Regex: b.MatchRouteRegex,
				},
			},
		},
		Action: &envoyroutev3.Route_Route{
			Route: &envoyroutev3.RouteAction{
				ClusterSpecifier: &envoyroutev3.RouteAction_Cluster{Cluster: b.clusterName},
			},
		},
		RequestHeadersToAdd:    requestHeaderToAdd,
		RequestHeadersToRemove: b.HeaderAmendments.RemoveHeaders,
	}
}

// buildEnvoyAdminConfig returns the envoy admin configuration.
func buildEnvoyAdminConfig() *envoyconfigbootstrapv3.Admin {
	admin := &envoyconfigbootstrapv3.Admin{
		Address: &envoyconfigcorev3.Address{
			Address: &envoyconfigcorev3.Address_SocketAddress{
				SocketAddress: &envoyconfigcorev3.SocketAddress{
					Address: envoyListenerAddress,
					PortSpecifier: &envoyconfigcorev3.SocketAddress_PortValue{
						PortValue: AdminPort,
					},
				},
			},
		},
	}
	return admin
}

func (hm HeaderMutations) toHttpFilter() *envoyconfigmanagerv3.HttpFilter {
	var headerMutations = make([]*envoymutationrulesv3.HeaderMutation, len(hm))
	for i, h := range hm {
		headerMutations[i] = &envoymutationrulesv3.HeaderMutation{
			Action: &envoymutationrulesv3.HeaderMutation_Append{
				Append: &envoyconfigcorev3.HeaderValueOption{
					Header: &envoyconfigcorev3.HeaderValue{
						Key:   h.SetHeader,
						Value: h.FromValue.String(),
					},
					AppendAction:   envoyconfigcorev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					KeepEmptyValue: false,
				},
			},
		}
	}

	filter := envoyheadermutationv3.HeaderMutation{
		Mutations: &envoyheadermutationv3.Mutations{
			RequestMutations: headerMutations,
		},
	}

	filterPB, err := anypb.New(&filter)
	if err != nil {
		panic(err)
	}

	return &envoyconfigmanagerv3.HttpFilter{
		Name: "envoy.filters.http.header_mutation",
		ConfigType: &envoyconfigmanagerv3.HttpFilter_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
				Value:   filterPB.GetValue(),
			},
		},
	}
}

func (jwts JWTProviders) toClusters() []*envoyconfigclusterv3.Cluster {
	var clusters []*envoyconfigclusterv3.Cluster
	for name, jwt := range jwts {
		clusters = append(clusters, jwt.toCluster(name))
	}
	return clusters
}

func (jwt JWTProvider) toCluster(name string) *envoyconfigclusterv3.Cluster {
	scheme := "https"
	port := uint32(443)
	if jwt.RemoteJWKsURI.Port != 0 {
		port = jwt.RemoteJWKsURI.Port
	}

	url, err := url.Parse(jwt.RemoteJWKsURI.URI)
	if err != nil {
		panic(err)
	}
	address := url.Hostname()

	return buildEnvoyCluster(getJWTClusterName(name), scheme, address, port, envoyconfigclusterv3.Cluster_STRICT_DNS)
}

func getJWTClusterName(name string) string {
	return fmt.Sprintf("%s_jwt", name)
}

func (bja BackendJWTAuth) toHttpFilter(matchPrefixRegex string) *envoyconfigmanagerv3.HttpFilter {
	providerName := getJWTClusterName(bja.ProviderName)
	rt := &envoyjwtauthnv3.RequirementRule_Requires{
		Requires: &envoyjwtauthnv3.JwtRequirement{
			RequiresType: &envoyjwtauthnv3.JwtRequirement_ProviderName{
				ProviderName: providerName,
			},
		},
	}
	rr := []*envoyjwtauthnv3.RequirementRule{
		{
			RequirementType: rt,
			Match: &envoyroutev3.RouteMatch{
				PathSpecifier: &envoyroutev3.RouteMatch_SafeRegex{SafeRegex: &envoymatcher.RegexMatcher{Regex: matchPrefixRegex}},
			},
		},
	}

	auth := &envoyjwtauthnv3.JwtAuthentication{
		Providers: map[string]*envoyjwtauthnv3.JwtProvider{
			providerName: {
				Issuer:            bja.provider.Issuer,
				Audiences:         bja.Audiences,
				PayloadInMetadata: tokenMetadataKey,
				JwksSourceSpecifier: &envoyjwtauthnv3.JwtProvider_RemoteJwks{
					RemoteJwks: &envoyjwtauthnv3.RemoteJwks{
						HttpUri: &envoyconfigcorev3.HttpUri{
							Uri: bja.provider.RemoteJWKsURI.URI,
							HttpUpstreamType: &envoyconfigcorev3.HttpUri_Cluster{
								Cluster: providerName,
							},
							Timeout: &pbduration.Duration{
								Seconds: 5,
							},
						},
					},
				},
			},
		},
		Rules: rr,
	}

	authPB, err := anypb.New(auth)
	if err != nil {
		panic(err)
	}

	jwtHTTPFilter := &envoyconfigmanagerv3.HttpFilter{
		Name: "envoy.filters.http.jwt_authn",
		ConfigType: &envoyconfigmanagerv3.HttpFilter_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
				Value:   authPB.Value,
			},
		},
	}
	return jwtHTTPFilter
}

func (c CELPolicies) toHttpFilter() *envoyconfigmanagerv3.HttpFilter {
	if len(c) == 0 {
		return nil
	}

	p, err := parser.NewParser()
	if err != nil {
		panic(err)
	}

	policies := make(map[string]*rbacv3.Policy)
	for k, expr := range c {
		expr = strings.Replace(expr, "token.", tokenInMetadataPathJWT, -1)
		ss := common.NewStringSource(expr, k)
		parsedAST, issues := p.Parse(ss)
		if issues != nil && len(issues.GetErrors()) > 0 {
			panic(fmt.Errorf("failed to parse CEL expression: %v", issues.GetErrors()))
		}

		a, err := ast.ToProto(parsedAST)
		if err != nil {
			panic(fmt.Errorf("failed to convert AST to proto: %v", err))
		}

		policy := &rbacv3.Policy{
			Permissions: []*rbacv3.Permission{
				{
					Rule: &rbacv3.Permission_Any{
						Any: true,
					},
				},
			},
			Principals: []*rbacv3.Principal{
				{
					Identifier: &rbacv3.Principal_Any{
						Any: true,
					},
				},
			},
			Condition: &v1alpha1.Expr{
				Id:       1,
				ExprKind: a.Expr.ExprKind,
			},
		}
		policies[k] = policy
	}

	rbac := envoyrbacv3filter.RBAC{
		Rules: &rbacv3.RBAC{
			Action:   rbacv3.RBAC_ALLOW,
			Policies: policies,
		},
	}

	rbacPB, err := anypb.New(&rbac)
	if err != nil {
		panic(err)
	}

	filter := &envoyconfigmanagerv3.HttpFilter{
		Name: "envoy.filters.http.rbac",
		ConfigType: &envoyconfigmanagerv3.HttpFilter_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
				Value:   rbacPB.GetValue(),
			},
		},
	}

	return filter
}

func (m *MTLSConfig) toTransportSocket() *envoyconfigcorev3.TransportSocket {
	dt := envoytlsv3.DownstreamTlsContext{
		RequireClientCertificate: &wrappers.BoolValue{Value: true},
		CommonTlsContext: &envoytlsv3.CommonTlsContext{
			TlsCertificates: []*envoytlsv3.TlsCertificate{
				{
					CertificateChain: &envoyconfigcorev3.DataSource{
						Specifier: &envoyconfigcorev3.DataSource_Filename{
							Filename: m.ServerCert,
						},
					},
					PrivateKey: &envoyconfigcorev3.DataSource{
						Specifier: &envoyconfigcorev3.DataSource_Filename{
							Filename: m.ServerKey,
						},
					},
				},
			},
			ValidationContextType: &envoytlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoytlsv3.CertificateValidationContext{
					TrustedCa: &envoyconfigcorev3.DataSource{
						Specifier: &envoyconfigcorev3.DataSource_Filename{
							Filename: m.TrustedCA,
						},
					},
				},
			},
		},
	}

	dtPB, err := anypb.New(&dt)
	if err != nil {
		panic(err)
	}

	return &envoyconfigcorev3.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &envoyconfigcorev3.TransportSocket_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
				Value:   dtPB.GetValue(),
			},
		},
	}
}
