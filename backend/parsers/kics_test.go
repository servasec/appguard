package parsers

import (
	"testing"
)

func TestParseKics(t *testing.T) {
	data := []byte(`{
  "files_scanned": 1,
  "queries": [
    {
      "query_name": "Metadata Without Version Constraint",
      "query_id": "84e5d5f5-8f40-4a7e-9a84-9f7d957d7c3a",
      "severity": "HIGH",
      "platform": "Terraform",
      "description": "Metadata without version constraint",
      "category": "Best Practices",
      "files": [
        {
          "file_name": "main.tf",
          "line": 4
        }
      ]
    }
  ]
}`)

	findings, err := ParseKics(data, "kics.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "84e5d5f5-8f40-4a7e-9a84-9f7d957d7c3a" {
		t.Errorf("unexpected rule id: %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "/main.tf" {
		t.Errorf("expected /main.tf, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 4 {
		t.Errorf("expected line 4, got %v", f.LineStart)
	}
}

func TestParseKics_Empty(t *testing.T) {
	findings, err := ParseKics([]byte(`{"queries": []}`), "kics.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseKics_InvalidJSON(t *testing.T) {
	_, err := ParseKics([]byte(`not json`), "kics.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
