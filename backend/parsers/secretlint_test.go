package parsers

import (
	"testing"
)

func TestParseSecretlint(t *testing.T) {
	data := []byte(`{
  "messages": [
    {
      "message": "found AWS key",
      "filePath": "src/config.js",
      "line": 3,
      "column": 5,
      "ruleId": "@secretlint/secretlint-rule-aws-access-key"
    }
  ]
}`)

	findings, err := ParseSecretlint(data, "secretlint.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "@secretlint/secretlint-rule-aws-access-key" {
		t.Errorf("unexpected rule id: %s", f.RuleID)
	}
	if f.FilePath != "/src/config.js" {
		t.Errorf("expected /src/config.js, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 3 {
		t.Errorf("expected line 3, got %v", f.LineStart)
	}
}

func TestParseSecretlint_Empty(t *testing.T) {
	findings, err := ParseSecretlint([]byte(`{"messages": []}`), "secretlint.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseSecretlint_InvalidJSON(t *testing.T) {
	_, err := ParseSecretlint([]byte(`not json`), "secretlint.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
