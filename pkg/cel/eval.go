package cel

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/interpreter"
	"google.golang.org/protobuf/types/known/structpb"

	k8s "k8s.io/apiserver/pkg/cel/library"
)

type EvalResponse struct {
	Result any     `json:"result"`
	Cost   *uint64 `json:"cost,omitempty"`
}

var celEnvOptions = []cel.EnvOption{
	cel.HomogeneousAggregateLiterals(),
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
	k8s.URLs(),
	k8s.Regex(),
	k8s.Lists(),
	cel.CrossTypeNumericComparisons(true),
	cel.OptionalTypes(),
	cel.ASTValidators(
		cel.ValidateDurationLiterals(),
		cel.ValidateTimestampLiterals(),
		cel.ValidateRegexLiterals(),
		cel.ValidateHomogeneousAggregateLiterals(),
	),
	ext.Strings(ext.StringsVersion(2)),
	ext.Sets(),
	cel.CostEstimatorOptions(checker.PresenceTestHasCost(false)),
}

var celProgramOptions = []cel.ProgramOption{
	cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
	cel.CostTrackerOptions(interpreter.PresenceTestHasCost(false)),
}

// EvalPB evaluates the cel expression against the given input.
func EvalPB(exp []byte, key string, input *structpb.Struct) (bool, error) {
	decl := []cel.EnvOption{cel.Declarations(decls.NewVar(key, decls.NewObjectType("google.protobuf.Struct")))}
	e, err := cel.NewEnv(append(celEnvOptions, decl...)...)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL env: %w", err)
	}
	return eval(string(exp), map[string]any{key: input}, e)
}

// Eval evaluates the cel expression against the given input.
// input is expected to be a json string
func Eval(exp string, input []byte) (bool, error) {
	var inputMap map[string]any
	if err := json.Unmarshal(input, &inputMap); err != nil {
		return false, fmt.Errorf("failed to decode input: %w", err)
	}
	return evalMap(exp, inputMap)
}

func EvalMap(exp string, input map[string]any) (bool, error) {
	return evalMap(exp, input)
}

func evalMap(exp string, input map[string]any) (bool, error) {
	inputVars := make([]cel.EnvOption, 0, len(input))
	for k := range input {
		inputVars = append(inputVars, cel.Variable(k, cel.DynType))
	}
	env, err := cel.NewEnv(append(celEnvOptions, inputVars...)...)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL env: %w", err)
	}
	return eval(exp, input, env)
}

// eval evaluates the cel expression against the given input
func eval(exp string, input map[string]any, env *cel.Env) (bool, error) {
	ast, issues := env.Compile(exp)
	if issues != nil {
		return false, fmt.Errorf("failed to compile the CEL expression: %s", issues.String())
	}
	prog, err := env.Program(ast, celProgramOptions...)
	if err != nil {
		return false, fmt.Errorf("failed to instantiate CEL program: %w", err)
	}
	val, costTracker, err := prog.Eval(input)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate: %w", err)
	}

	response, err := generateResponse(val, costTracker)
	if err != nil {
		return false, fmt.Errorf("failed to generate the response: %w", err)
	}
	result, ok := response.Result.(*structpb.Value)
	if !ok {
		return false, fmt.Errorf("failed to convert the result to structpb.Value")
	}
	return result.GetBoolValue(), nil
}

func getResults(val *ref.Val) (any, error) {
	if value, err := (*val).ConvertToNative(reflect.TypeOf(&structpb.Value{})); err != nil {
		return nil, err
	} else {
		return value, nil
	}
}

func generateResponse(val ref.Val, costTracker *cel.EvalDetails) (*EvalResponse, error) {
	result, evalError := getResults(&val)
	if evalError != nil {
		return nil, evalError
	}
	cost := costTracker.ActualCost()
	return &EvalResponse{
		Result: result,
		Cost:   cost,
	}, nil
}
