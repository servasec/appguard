package parsers

import (
	"testing"
)

func TestParseCargoAudit(t *testing.T) {
	data := []byte(`{
  "database": {"advisory-count": 500},
  "lockfile": {"name": "example", "version": "0.1.0"},
  "vulnerabilities": {
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2023-0001",
          "title": "Uncontrolled recursion in example",
          "description": "A stack overflow can happen",
          "url": "https://rustsec.org/advisories/RUSTSEC-2023-0001",
          "cwe": ["CWE-674"],
          "severity": "high"
        },
        "versions": {"patched": [">=1.2.3"], "unaffected": []},
        "package": {"name": "example", "version": "1.2.0"}
      }
    ]
  }
}`)

	findings, err := ParseCargoAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "RUSTSEC-2023-0001" {
		t.Errorf("expected RUSTSEC-2023-0001, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.CWEID != "CWE-674" {
		t.Errorf("expected CWE-674, got %s", f.CWEID)
	}
	if f.Remediation != "Upgrade example to >=1.2.3" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
	if f.FilePath != "example@1.2.0" {
		t.Errorf("expected example@1.2.0, got %s", f.FilePath)
	}
}

func TestParseCargoAudit_Empty(t *testing.T) {
	findings, err := ParseCargoAudit([]byte(`{"vulnerabilities": {"list": []}}`), "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseCargoAudit_InvalidJSON(t *testing.T) {
	_, err := ParseCargoAudit([]byte(`not json`), "audit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
