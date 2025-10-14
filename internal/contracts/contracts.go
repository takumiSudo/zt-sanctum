package contracts

import (
	"encoding/json"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type Contract struct {
	ID     string
	Schema *jsonschema.Schema
}

// Load compiles a JSON-Schema from a local path and returns the schema + its $id (if present).
func Load(path string) (*Contract, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// best-effort: read $id
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	id, _ := raw["$id"].(string)

	compiler := jsonschema.NewCompiler()
	// easiest for local files: file://<path>
	sch, err := compiler.Compile("file://" + path)
	if err != nil {
		return nil, err
	}
	return &Contract{ID: id, Schema: sch}, nil
}