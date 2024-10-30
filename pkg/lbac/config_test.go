package lbac

import (
	"fmt"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

func TestRawPolicyToPolicy(t *testing.T) {
	tests := []struct {
		name              string
		input             []byte
		wantErr           bool
		wantName          string
		wantSelectors     []*labels.Matcher
		wantCondSelectors []*labels.Matcher
	}{
		{
			name: "MissingName",
			input: []byte(`
- expression: "request.method == 'GET'"
  selectors:
    - label_selector: "{foo='bar'}"
`),
			wantErr:           true,
			wantName:          "",
			wantSelectors:     nil,
			wantCondSelectors: nil,
		},
		{
			name: "MissingExpression",
			input: []byte(`
- name: policy1
  selectors:
    - label_selector: "{foo='bar'}"
`),
			wantErr:           true,
			wantName:          "",
			wantSelectors:     nil,
			wantCondSelectors: nil,
		},
		{
			name: "InvalidLabelSelector",
			input: []byte(`
- name: policy1
  expression: "request.method == 'GET'"
  selectors:
    - label_selector: "invalid selector"
`),
			wantErr:           true,
			wantName:          "",
			wantSelectors:     nil,
			wantCondSelectors: nil,
		},
		{
			name: "ValidInputWithConditionalSelector",
			input: []byte(`
- name: policy1
  expression: "request.method == 'GET'"
  selectors:
    - label_selector: "{foo='bar'}"
      conditional_selector: "{baz='qux'}"
`),
			wantErr:  false,
			wantName: "policy1",
			wantSelectors: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "foo", Value: "bar"},
			},
			wantCondSelectors: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "baz", Value: "qux"},
			},
		},
		{
			name: "ValidInputWithoutConditionalSelector",
			input: []byte(`
- name: policy1
  expression: "request.method == 'GET'"
  selectors:
    - label_selector: "{foo='bar'}"
`),
			wantErr:  false,
			wantName: "policy1",
			wantSelectors: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "foo", Value: "bar"},
			},
			wantCondSelectors: nil,
		},
		{
			name: "InvalidConditionalSelector",
			input: []byte(`
- name: policy1
  expression: "request.method == 'GET'"
  selectors:
    - label_selector: "{foo='bar'}"
      conditional_selector: "invalid selector"
`),
			wantErr:           true,
			wantName:          "",
			wantSelectors:     nil,
			wantCondSelectors: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := RawPolicyToPolicy(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("RawPolicyToPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(policies) == 0 || policies[0].Name != tt.wantName {
					t.Errorf("RawPolicyToPolicy() policy name = %v, wantName %v", policies[0].Name, tt.wantName)
				}
				if len(policies[0].Selectors) != len(tt.wantSelectors) {
					t.Errorf("RawPolicyToPolicy() selectors length = %v, want %v", len(policies[0].Selectors), len(tt.wantSelectors))
				}
				for i, matcher := range policies[0].Selectors {
					if matcher.LabelSelector[0].Type != tt.wantSelectors[i].Type || matcher.LabelSelector[0].Name != tt.wantSelectors[i].Name || matcher.LabelSelector[0].Value != tt.wantSelectors[i].Value {
						t.Errorf("RawPolicyToPolicy() matcher = %v, want %v", matcher.LabelSelector[0], tt.wantSelectors[i])
					}
					if len(matcher.ConditionalSelector) != len(tt.wantCondSelectors) {
						t.Errorf("RawPolicyToPolicy() conditional selectors length = %v, want %v", len(matcher.ConditionalSelector), len(tt.wantCondSelectors))
					}
					for j, condMatcher := range matcher.ConditionalSelector {
						if condMatcher.Type != tt.wantCondSelectors[j].Type || condMatcher.Name != tt.wantCondSelectors[j].Name || condMatcher.Value != tt.wantCondSelectors[j].Value {
							t.Errorf("RawPolicyToPolicy() conditional matcher = %v, want %v", condMatcher, tt.wantCondSelectors[j])
						}
					}
				}
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		policy     Policy
		state      map[string]any
		wantResult bool
		wantErr    bool
	}{
		{
			name: "ValidExpression",
			policy: Policy{
				CELExpression: "request.method == 'GET'",
			},
			state: map[string]any{
				"request.method": "GET",
			},
			wantResult: true,
			wantErr:    false,
		},
		{
			name: "InvalidExpression",
			policy: Policy{
				CELExpression: "invalid expression",
			},
			state:      map[string]any{},
			wantResult: false,
			wantErr:    true,
		},
		{
			name: "ExpressionEvaluatesToFalse",
			policy: Policy{
				CELExpression: "request.method == 'POST'",
			},
			state: map[string]any{
				"request.method": "GET",
			},
			wantResult: false,
			wantErr:    false,
		},
		{
			name: "EmptyExpression",
			policy: Policy{
				CELExpression: "",
			},
			state:      map[string]any{},
			wantResult: false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.policy.Evaluate(tt.state)
			if (err != nil) != tt.wantErr {
				t.Errorf("Evaluate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.wantResult {
				t.Errorf("Evaluate() result = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

func TestApplyPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		expr    string
		wantErr bool
		expect  string
	}{
		{
			name: "ValidPolicyWithoutConditionalSelector",
			policy: Policy{
				Selectors: []Selector{
					{
						LabelSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "foo", Value: "bar"},
						},
					},
				},
			},
			expr:    `up{test="test"}`,
			expect:  `up{foo="bar",test="test"}`,
			wantErr: false,
		},
		{
			name: "ValidPolicyWithConditionalSelector",
			policy: Policy{
				Selectors: []Selector{
					{
						LabelSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "foo", Value: "bar"},
						},
						ConditionalSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "baz", Value: "qux"},
						},
					},
					{
						LabelSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "some", Value: "value"},
						},
						ConditionalSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "__name__", Value: "up"},
						},
					},
					{
						LabelSelector: []*labels.Matcher{
							{Type: labels.MatchEqual, Name: "expect", Value: "skip"},
						},
					},
				},
			},
			expr:    `up{some="value",test="test"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedExpr, err := parser.ParseExpr(tt.expr)
			if err != nil {
				t.Fatalf(err.Error())
			}
			err = tt.policy.Apply(parsedExpr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Apply() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Println(parsedExpr.String())
		})
	}
}

func TestRawPolicyToFilterMetadata(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "ValidInput",
			input: []byte(`
  - name: policy1
    expression: "request.method == 'GET'"
    selectors:
      - label_selector: "{foo='bar'}"
`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RawPolicyToFilterMetadata(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("RawPolicyToFilterMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
