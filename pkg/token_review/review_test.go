package token_review

import (
	"testing"

	authv1 "k8s.io/api/authentication/v1"
)

func TestStatusToValue_ValidTokenReview(t *testing.T) {
	tr := &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User: authv1.UserInfo{
				Username: "test-user",
				UID:      "test-UID",
				Groups:   []string{"test-group"},
				Extra: map[string]authv1.ExtraValue{
					"test-key": []string{"test-value"},
				},
			},
			Audiences: []string{"test-audience"},
		},
	}

	value := StatusToValue("status", tr.Status)
	if value == nil {
		t.Fatalf("expected value, got nil")
	}
	if value["status"].GetStructValue().Fields["authenticated"].GetBoolValue() != true {
		t.Fatalf("expected authenticated true, got %v", value["status"].GetStructValue().Fields["authenticated"].GetBoolValue())
	}
	if value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Username"].GetStringValue() != "test-user" {
		t.Fatalf("expected Username test-user, got %s", value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Username"].GetStringValue())
	}
	if value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["UID"].GetStringValue() != "test-UID" {
		t.Fatalf("expected UID test-UID, got %s", value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["UID"].GetStringValue())
	}
	if value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Groups"].GetListValue().Values[0].GetStringValue() != "test-group" {
		t.Fatalf("expected group test-group, got %s", value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Groups"].GetListValue().Values[0].GetStringValue())
	}
	if value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Extra"].GetStructValue().Fields["test-key"].GetListValue().Values[0].GetStringValue() != "test-value" {
		t.Fatalf("expected Extra test-value, got %s", value["status"].GetStructValue().Fields["user"].GetStructValue().Fields["Extra"].GetStructValue().Fields["test-key"].GetListValue().Values[0].GetStringValue())
	}
	if value["status"].GetStructValue().Fields["audiences"].GetListValue().Values[0].GetStringValue() != "test-audience" {
		t.Fatalf("expected audience test-audience, got %s", value["status"].GetStructValue().Fields["audiences"].GetListValue().Values[0].GetStringValue())
	}
}

func TestStatusToValue_InvalidTokenReview(t *testing.T) {
	tr := &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{
			Authenticated: false,
		},
	}

	value := StatusToValue("status", tr.Status)
	if value == nil {
		t.Fatalf("expected value, got nil")
	}
	if value["status"].GetStructValue().Fields["authenticated"].GetBoolValue() != false {
		t.Fatalf("expected authenticated false, got %v", value["status"].GetStructValue().Fields["authenticated"].GetBoolValue())
	}
}
