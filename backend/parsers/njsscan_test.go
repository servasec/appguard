package parsers

import (
	"testing"
)

func TestParseNjsscan(t *testing.T) {
	data := []byte(`{
  "files": {
    "routes/admin.js": [
      {
        "title": "Database Injection",
        "description": "Possible SQL injection",
        "hash": "0945a3cd9984dfee979c18e68a44413e",
        "line": 12,
        "match": "db.query(req.body.id)",
        "metadata": {
          "cwe": "CWE-89",
          "severity": "HIGH",
          "owasp": "A1"
        }
      }
    ]
  }
}`)

	findings, err := ParseNjsscan(data, "scan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "0945a3cd9984dfee979c18e68a44413e" {
		t.Errorf("unexpected rule id: %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.CWEID != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", f.CWEID)
	}
	if f.FilePath != "/routes/admin.js" {
		t.Errorf("expected /routes/admin.js, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 12 {
		t.Errorf("expected line 12, got %v", f.LineStart)
	}
}

func TestParseNjsscan_Empty(t *testing.T) {
	findings, err := ParseNjsscan([]byte(`{"files": {}}`), "scan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseNjsscan_InvalidJSON(t *testing.T) {
	_, err := ParseNjsscan([]byte(`not json`), "scan.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
