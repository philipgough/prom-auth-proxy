package lbac

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/philipgough/prom-auth-proxy/pkg/cel"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	ServerName               = "envoy.filters.http.ext_proc"
	ServerDefaultPort        = 3001
	DefaultMetadataNamespace = "lbac"
	DefaultPolicySubKey      = "policies"
	DefaultStateSubKey       = "state"
	DefaultStateNamespace    = "namespace"
	DefaultStateKey          = "key"
)

// Policies is a list of Policy.
type Policies []Policy

// Policy is a list of CEL expressions and matchers.
// If all the CELExpressions evaluate to true the Selectors are injected into the request.
type Policy struct {
	// Name is a human-readable name for the policy.
	Name string `json:"name"`
	// CELExpression is a CEL expression that must evaluate to true for the policy to be applied.
	CELExpression string `json:"expression"`
	// Selectors is a list of matchers to be injected into the request as part of the policy if the CELExpression evaluates to true.
	Selectors []Selector `json:"selectors"`
}

type Selector struct {
	// LabelSelector is the label selector that will be applied if all the selectors in the ConditionalSelector are true.
	LabelSelector []*labels.Matcher `json:"label_selector"`
	// ConditionalSelector is a list of selectors that must all evaluate to true for the Selector to be applied.
	// This is optional and if not present the Selector will be applied if the CELExpression evaluates to true.
	ConditionalSelector []*labels.Matcher `json:"conditional_selector,omitempty"`
}

// RawSelector is a list of selectors in string form.
type RawSelector struct {
	// LabelSelector is the label selector that will be applied if all the selectors in the ConditionalSelector are true.
	LabelSelector string `json:"label_selector"`
	// ConditionalSelector is a list of selectors that must all evaluate to true for the Selector to be applied.
	// This is optional and if not present the Selector will be applied if the CELExpression evaluates to true.
	ConditionalSelector *string `json:"conditional_selector,omitempty"`
}

// Evaluate evaluates the policy against the source.
func (p Policy) Evaluate(againstState map[string]any) (bool, error) {
	return cel.EvalMap(p.CELExpression, againstState)
}

// RawPolicy is a list of CEL expressions and matchers in string form.
type RawPolicy struct {
	Name string `json:"name"`
	// CELExpression is a CEL expression that must evaluate to true for the policy to be applied.
	CELExpression string `json:"expression"`
	// Selectors is a list of label selectors/matcher in string format to be injected into the request as part of the policy.
	Selectors []RawSelector `json:"selectors"`
}

// RawPolicyToPolicy converts a raw policy to a policy.
func RawPolicyToPolicy(b []byte) (Policies, error) {
	var rawPolicies []RawPolicy
	err := yaml.Unmarshal(b, &rawPolicies)
	if err != nil {
		return nil, err
	}

	var lbacPolicies Policies
	for _, rawPolicy := range rawPolicies {
		if rawPolicy.CELExpression == "" {
			return nil, fmt.Errorf("policy %s must have a CEL expression", rawPolicy.Name)
		}

		if rawPolicy.Name == "" {
			return nil, fmt.Errorf("policy name cannot be empty")
		}

		if len(rawPolicy.Selectors) == 0 {
			return nil, fmt.Errorf("policy %s must have at least one matcher", rawPolicy.Name)
		}
		_, err := cel.Parse(rawPolicy.CELExpression, rawPolicy.Name)
		if err != nil {
			return nil, fmt.Errorf("error parsing CEL expression %s: %v", rawPolicy.CELExpression, err)
		}

		var selectors []Selector
		for _, matcher := range rawPolicy.Selectors {
			selector, err := parser.ParseMetricSelector(matcher.LabelSelector)
			if err != nil {
				return nil, fmt.Errorf("error parsing matcher %s: %v", matcher.LabelSelector, err)
			}

			s := Selector{LabelSelector: selector}
			if matcher.ConditionalSelector != nil {
				conditionalSelectors, err := parser.ParseMetricSelector(*matcher.ConditionalSelector)
				if err != nil {
					return nil, fmt.Errorf("error parsing conditional matcher %s: %v", *matcher.ConditionalSelector, err)
				}
				s.ConditionalSelector = conditionalSelectors
			}
			selectors = append(selectors, s)
		}
		lbacPolicies = append(lbacPolicies, Policy{
			Name:          rawPolicy.Name,
			CELExpression: rawPolicy.CELExpression,
			Selectors:     selectors,
		})
	}

	return lbacPolicies, nil
}
