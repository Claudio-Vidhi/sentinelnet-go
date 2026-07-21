package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestContextCharBudgetGolden(t *testing.T) {
	var cases []struct {
		Provider, Model string
		Override, Want  int
	}
	readJSON(t, "budget.json", &cases)
	for _, c := range cases {
		if got := ContextCharBudget(c.Provider, c.Model, c.Override); got != c.Want {
			t.Errorf("ContextCharBudget(%q,%q,%d) = %d, atteso %d", c.Provider, c.Model, c.Override, got, c.Want)
		}
	}
}

func TestFitContextGolden(t *testing.T) {
	var cases []struct {
		Blocks   []string
		Budget   int
		Question string
		Want     []string
	}
	readJSON(t, "fit_context.json", &cases)
	for i, c := range cases {
		got := FitContext(c.Blocks, c.Budget, c.Question)
		if !reflect.DeepEqual(got, c.Want) {
			t.Errorf("caso %d (budget=%d q=%q): FitContext diverso dal Python\n--- Go ---\n%#v\n--- Py ---\n%#v", i, c.Budget, c.Question, got, c.Want)
		}
	}
}

func readJSON(t *testing.T, name string, dst any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatal(err)
	}
}
