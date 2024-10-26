package cel

import (
	"fmt"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Parse parses the given expression and returns the AST.
func Parse(expression, description string) (*ast.AST, error) {
	p, err := parser.NewParser()
	if err != nil {
		return nil, err
	}

	ss := common.NewStringSource(expression, description)
	parsedAST, issues := p.Parse(ss)
	if issues != nil && len(issues.GetErrors()) > 0 {
		return nil, fmt.Errorf("failed to parse CEL expression: %v", issues.GetErrors())
	}
	return parsedAST, nil
}

// ToProto returns a checked expression or an error
func ToProto(a *ast.AST) (*expr.CheckedExpr, error) {
	return ast.ToProto(a)
}
