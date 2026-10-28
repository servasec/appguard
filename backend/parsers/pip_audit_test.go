package parsers

import (
	"testing"
)

func TestParsePipAudit(t *testing.T) {
	data := []byte(`{
  "dependencies": [
    {
      "name": "requests",
      "version": "2.25.1",
      "vulns": [
        {
          "id": "PYSEC-2023-74",
          "description": "Unintended leak of proxy authentication",
          "fix_versions": ["2.31.0"],
          "affected_ranges": [">=2.25,<2.31.0"]
        }
      ]
    },
    {
      "name": "flask",
      "version": "2.0.0",
      "vulns": []
    }
  ]
}`)

	findings, err := ParsePipAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "PYSEC-2023-74" {
		t.Errorf("expected PYSEC-2023-74, got %s", f.RuleID)
	}
	if f.Title != "Unintended leak of proxy authentication" {
		t.Errorf("unexpected title: %s", f.Title)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium, got %s", f.Severity)
	}
	if f.FilePath != "requests@2.25.1" {
		t.Errorf("expected requests@2.25.1, got %s", f.FilePath)
	}
	if f.Remediation != "Upgrade requests to 2.31.0" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParsePipAudit_MultipleVulns(t *testing.T) {
	data := []byte(`{
  "dependencies": [
    {
      "name": "django",
      "version": "3.2.0",
      "vulns": [
        {"id": "PYSEC-2023-100", "description": "SQL injection", "fix_versions": ["3.2.19"]},
        {"id": "PYSEC-2023-101", "description": "XSS vulnerability", "fix_versions": ["3.2.19"]}
      ]
    }
  ]
}`)

	findings, err := ParsePipAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].RuleID != "PYSEC-2023-100" {
		t.Errorf("expected PYSEC-2023-100, got %s", findings[0].RuleID)
	}
	if findings[1].RuleID != "PYSEC-2023-101" {
		t.Errorf("expected PYSEC-2023-101, got %s", findings[1].RuleID)
	}
}

func TestParsePipAudit_Empty(t *testing.T) {
	findings, err := ParsePipAudit([]byte(`{"dependencies": []}`), "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParsePipAudit_InvalidJSON(t *testing.T) {
	_, err := ParsePipAudit([]byte(`not json`), "audit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
