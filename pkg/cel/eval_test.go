package cel

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"google.golang.org/protobuf/types/known/structpb"
)

var i = []byte(`{
"object": {
	"replicas": 2,
    "href":     "https://user:pass@example.com:80/path?query=val#fragment",
    "image":    "registry.com/image:v0.0.0",
	"items":    [1, 2, 3],
	"abc":      ["a", "b", "c"]
 }
}
`)

func TestEval(t *testing.T) {
	tests := []struct {
		name    string
		exp     string
		want    any
		wantErr bool
	}{
		{
			name: "lte",
			exp:  "object.replicas <= 5",
			want: true,
		},
		{
			name:    "error",
			exp:     "object.",
			wantErr: true,
		},
		{
			name: "url",
			exp:  "isURL(object.href) && url(object.href).getScheme() == 'https' && url(object.href).getEscapedPath() == '/path'",
			want: true,
		},
		{
			name: "list",
			exp:  "object.items.isSorted() && object.items.sum() == 6 && object.items.max() == 3 && object.items.indexOf(1) == 0",
			want: true,
		},
		{
			name: "cross type numeric comparisons",
			exp:  "object.replicas > 1.4",
			want: true,
		},
		{
			name: "split",
			exp:  "object.image.split(':').size() == 2",
			want: true,
		},
		{
			name: "sets.contains test 1",
			exp:  `sets.contains([], [])`,
			want: true,
		},
		{
			name: "sets.contains test 2",
			exp:  `sets.contains([], [1])`,
			want: false,
		},
		{
			name: "sets.contains test 3",
			exp:  `sets.contains([1, 2, 3, 4], [2, 3])`,
			want: true,
		},
		{
			name: "sets.contains test 4",
			exp:  `sets.contains([1, 2, 3], [3, 2, 1])`,
			want: true,
		},
		{
			name: "sets.equivalent test 1",
			exp:  `sets.equivalent([], [])`,
			want: true,
		},
		{
			name: "sets.equivalent test 2",
			exp:  `sets.equivalent([1], [1, 1])`,
			want: true,
		},
		{
			name: "sets.equivalent test 3",
			exp:  `sets.equivalent([1], [1, 1])`,
			want: true,
		},
		{
			name: "sets.equivalent test 4",
			exp:  `sets.equivalent([1, 2, 3], [3, 2, 1])`,
			want: true,
		},

		{
			name: "sets.intersects test 1",
			exp:  `sets.intersects([1], [])`,
			want: false,
		},
		{
			name: "sets.intersects test 2",
			exp:  `sets.intersects([1], [1, 2])`,
			want: true,
		},
		{
			name: "sets.intersects test 3",
			exp:  `sets.intersects([[1], [2, 3]], [[1, 2], [2, 3]])`,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Eval(tt.exp, i)

			if (err != nil) != tt.wantErr {
				t.Errorf("eval() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if !reflect.DeepEqual(tt.want, got) {
					t.Errorf("Expected %v\n, received %v", tt.want, got)
				}
			}
		})
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name    string
		exp     string
		wantErr bool
	}{
		// Duration Literals
		{
			name:    "Duration Validation test 1",
			exp:     `duration('1')`,
			wantErr: true,
		},
		{
			name:    "Duration Validation test 2",
			exp:     `duration('1d')`,
			wantErr: true,
		},
		{
			name:    "Duration Validation test 3",
			exp:     `duration('1us') < duration('1nns')`,
			wantErr: true,
		},
		{
			name: "Duration Validation test 4",
			exp:  `duration('2h3m4s5us')`,
		},
		{
			name: "Duration Validation test 5",
			exp:  `duration(x)`,
		},

		// Timestamp Literals
		{
			name:    "Timestamp Validation test 1",
			exp:     `timestamp('1000-00-00T00:00:00Z')`,
			wantErr: true,
		},
		{
			name:    "Timestamp Validation test 2",
			exp:     `timestamp('1000-01-01T00:00:00ZZ')`,
			wantErr: true,
		},
		{
			name: "Timestamp Validation test 3",
			exp:  `timestamp('1000-01-01T00:00:00Z')`,
		},
		{
			name: "Timestamp Validation test 4",
			exp:  `timestamp(-6213559680)`, // min unix epoch time.
		},
		{
			name:    "Timestamp Validation test 5",
			exp:     `timestamp(-62135596801)`,
			wantErr: true,
		},
		{
			name: "Timestamp Validation test 6",
			exp:  `timestamp(x)`,
		},

		// Regex Literals
		{
			name: "Regex Validation test 1",
			exp:  `'hello'.matches('el*')`,
		},
		{
			name:    "Regex Validation test 2",
			exp:     `'hello'.matches('x++')`,
			wantErr: true,
		},
		{
			name:    "Regex Validation test 3",
			exp:     `'hello'.matches('(?<name%>el*)')`,
			wantErr: true,
		},
		{
			name:    "Regex Validation test 4",
			exp:     `'hello'.matches('??el*')`,
			wantErr: true,
		},
		{
			name: "Regex Validation test 5",
			exp:  `'hello'.matches(x)`,
		},

		// Homogeneous Aggregate Literals
		{
			name:    "Homogeneous Aggregate Validation test 1",
			exp:     `name in ['hello', 0]`,
			wantErr: true,
		},
		{
			name:    "Homogeneous Aggregate Validation test 2",
			exp:     `{'hello':'world', 1:'!'}`,
			wantErr: true,
		},
		{
			name:    "Homogeneous Aggregate Validation test 3",
			exp:     `name in {'hello':'world', 'goodbye':true}`,
			wantErr: true,
		},
		{
			name: "Homogeneous Aggregate Validation test 4",
			exp:  `name in ['hello', 'world']`,
		},
		{
			name: "Homogeneous Aggregate Validation test 5",
			exp:  `name in ['hello', ?optional.ofNonZeroValue('')]`,
		},
		{
			name: "Homogeneous Aggregate Validation test 6",
			exp:  `name in [?optional.ofNonZeroValue(''), 'hello', ?optional.of('')]`,
		},
		{
			name: "Homogeneous Aggregate Validation test 7",
			exp:  `name in {'hello': false, 'world': true}`,
		},
		{
			name: "Homogeneous Aggregate Validation test 8",
			exp:  `{'hello': false, ?'world': optional.ofNonZeroValue(true)}`,
		},
		{
			name: "Homogeneous Aggregate Validation test 9",
			exp:  `{?'hello': optional.ofNonZeroValue(false), 'world': true}`,
		},
	}
	env, err := cel.NewEnv(append(celEnvOptions,
		cel.Variable("x", types.StringType),
		cel.Variable("name", types.StringType),
	)...)
	if err != nil {
		t.Errorf("failed to create CEL env: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := env.Compile(tt.exp)
			if tt.wantErr {
				if issues.Err() == nil {
					t.Fatalf("Compilation should have failed, expr: %v", tt.exp)
				}
			} else if issues.Err() != nil {
				t.Fatalf("Compilation failed, expr: %v, error: %v", tt.exp, issues.Err())
			}
		})
	}
}

func TestEvalPB(t *testing.T) {
	tests := []struct {
		name    string
		exp     []byte
		key     string
		input   *structpb.Struct
		want    bool
		wantErr bool
	}{
		{
			name:  "ValidInput",
			exp:   []byte(`object.replicas <= 5`),
			key:   "object",
			input: &structpb.Struct{Fields: map[string]*structpb.Value{"replicas": structpb.NewNumberValue(2)}},
			want:  true,
		},
		{
			name:    "InvalidExpression",
			exp:     []byte(`object.`),
			key:     "object",
			input:   &structpb.Struct{Fields: map[string]*structpb.Value{"replicas": structpb.NewNumberValue(2)}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvalPB(tt.exp, tt.key, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvalPB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EvalPB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalFromPB(t *testing.T) {
	input := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"replicas": structpb.NewNumberValue(2),
			"token": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"group": structpb.NewStringValue("admin"),
				},
			}),
		},
	}

	ok, err := EvalMap(`token.group == 'admin'`, input.AsMap())
	if err != nil {
		t.Errorf("EvalMap() error = %v", err)
	}
	if !ok {
		t.Errorf("EvalMap() = %v, want %v", ok, true)
	}

}
