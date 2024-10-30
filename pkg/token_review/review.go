package token_review

import (
	"google.golang.org/protobuf/types/known/structpb"
	authv1 "k8s.io/api/authentication/v1"
)

const (
	// ServerName is the name of the server.
	ServerName = "envoy.filters.http.ext_authz"
	// ServerDefaultPort is the default port to listen on.
	ServerDefaultPort = 5001
	// DefaultMetadataNamespace is the default namespace to use for the metadata.
	DefaultMetadataNamespace = "token_review"
	// DefaultSubKey is the default sub-key to use for the metadata.
	DefaultSubKey = "token"
	// DefaultAuthHeader is the default header to extract the token from.
	DefaultAuthHeader = "authorization"
)

// Config is the configuration for the server.
type Config struct {
	// ExtractTokenFromHeader determines what header to extract the token from.
	// If true, the token will be extracted from the Authorization header.
	ExtractTokenFromHeader string `json:"extract_token_from_header"`
	// MetadataNamespace is the namespace to use for the metadata.
	MetaDataNamespace string `json:"metadata_namespace"`
	// TokenKey is the key to use for the token in the metadata.
	TokenKey string `json:"token_key"`
}

const (
	AuthenticatedKey = "authenticated"
	UserKey          = "user"
	AudiencesKey     = "audiences"
)

// keys for userinfo
const (
	Username = "username"
	UID      = "uid"
	Groups   = "groups"
	Extra    = "extra"
)

// StatusToValue converts a TokenReview.Status to a structpb.Value referenced by the key.
func StatusToValue(key string, trs authv1.TokenReviewStatus) map[string]*structpb.Value {
	userGroups := make([]*structpb.Value, len(trs.User.Groups))
	for i, group := range trs.User.Groups {
		userGroups[i] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: group}}
	}

	userExtra := make(map[string]*structpb.Value, len(trs.User.Extra))
	for k, v := range trs.User.Extra {
		values := make([]*structpb.Value, len(v))
		for i, val := range v {
			values[i] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: val}}
		}
		userExtra[k] = &structpb.Value{Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: values}}}
	}

	user := &structpb.Value_StructValue{StructValue: &structpb.Struct{
		Fields: map[string]*structpb.Value{
			Username: {Kind: &structpb.Value_StringValue{StringValue: trs.User.Username}},
			UID:      {Kind: &structpb.Value_StringValue{StringValue: trs.User.UID}},
			Groups:   {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: userGroups}}},
			Extra:    {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: userExtra}}},
		},
	},
	}
	userValue := &structpb.Value{Kind: user}

	audiences := make([]*structpb.Value, len(trs.Audiences))
	for i, audience := range trs.Audiences {
		audiences[i] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: audience}}
	}

	result := map[string]*structpb.Value{
		key: {
			Kind: &structpb.Value_StructValue{
				StructValue: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						AuthenticatedKey: {Kind: &structpb.Value_BoolValue{BoolValue: trs.Authenticated}},
						UserKey:          userValue,
						AudiencesKey:     {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: audiences}}},
					},
				},
			},
		},
	}
	return result
}
