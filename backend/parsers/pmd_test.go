package parsers

import (
	"testing"
)

func TestParsePmd(t *testing.T) {
	data := []byte(`{
  "formatVersion": 0,
  "pmdVersion": "6.55.0",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "files": [
    {
      "filename": "src/main/java/App.java",
      "violations": [
        {
          "beginline": 8,
          "endline": 8,
          "begincolumn": 1,
          "endcolumn": 5,
          "description": "Avoid using System.out.println",
          "rule": "SystemPrintln",
          "ruleset": "Best Practices",
          "priority": 2,
          "externalInfoUrl": "https://pmd.github.io/pmd-6.55.0/pmd_rules_java_bestpractices.html#systemprintln"
        }
      ]
    }
  ]
}`)

	findings, err := ParsePmd(data, "pmd.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SystemPrintln" {
		t.Errorf("expected SystemPrintln, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.LineStart == nil || *f.LineStart != 8 {
		t.Errorf("expected line 8, got %v", f.LineStart)
	}
	if f.LineEnd == nil || *f.LineEnd != 8 {
		t.Errorf("expected line 8 end, got %v", f.LineEnd)
	}
}

func TestParsePmd_PriorityLow(t *testing.T) {
	data := []byte(`{
  "files": [
    {
      "filename": "src/App.java",
      "violations": [
        {"beginline": 1, "endline": 1, "description": "minor issue", "rule": "CommentRequired", "priority": 5}
      ]
    }
  ]
}`)

	findings, err := ParsePmd(data, "pmd.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "low" {
		t.Errorf("expected low, got %s", findings[0].Severity)
	}
}

func TestParsePmd_Empty(t *testing.T) {
	findings, err := ParsePmd([]byte(`{"files": []}`), "pmd.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParsePmd_InvalidJSON(t *testing.T) {
	_, err := ParsePmd([]byte(`not json`), "pmd.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
