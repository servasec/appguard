package parsers

import (
	"testing"
)

func TestParsePnpmAudit(t *testing.T) {
	data := []byte(`{
  "report": {
    "vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0},
    "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0}, "dependencies": 5},
    "auditReport": {
      "vulnerabilities": {
        "lodash": [
          {
            "title": "Prototype Pollution",
            "description": "lodash is vulnerable to prototype pollution",
            "severity": "high"
          }
        ]
      }
    }
  }
}`)

	findings, err := ParsePnpmAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "lodash" {
		t.Errorf("expected lodash, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.Title != "Prototype Pollution" {
		t.Errorf("unexpected title: %s", f.Title)
	}
}

func TestParsePnpmAudit_Empty(t *testing.T) {
	findings, err := ParsePnpmAudit([]byte(`{"report": {"auditReport": {"vulnerabilities": {}}}}`), "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParsePnpmAudit_InvalidJSON(t *testing.T) {
	_, err := ParsePnpmAudit([]byte(`not json`), "audit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
