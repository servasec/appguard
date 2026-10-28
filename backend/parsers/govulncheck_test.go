package parsers

import (
	"testing"
)

func TestParseGovulncheck(t *testing.T) {
	data := []byte(`{
  "vulns": [
    {
      "osv": {
        "id": "GO-2024-2400",
        "summary": "Denial of service via multipart form parsing"
      },
      "aliases": ["CVE-2024-24790", "CWE-190"],
      "modules": [
        {
          "path": "net/http",
          "versions": "",
          "available": {"version": "", "next": "go1.22.4"}
        }
      ]
    }
  ]
}`)

	findings, err := ParseGovulncheck(data, "vuln.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "GO-2024-2400" {
		t.Errorf("expected GO-2024-2400, got %s", f.RuleID)
	}
	if f.Title != "Denial of service via multipart form parsing" {
		t.Errorf("unexpected title: %s", f.Title)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium, got %s", f.Severity)
	}
	if f.CWEID != "CWE-190" {
		t.Errorf("expected CWE-190, got %s", f.CWEID)
	}
	if f.Remediation != "Upgrade net/http to go1.22.4" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParseGovulncheck_Empty(t *testing.T) {
	findings, err := ParseGovulncheck([]byte(`{"vulns": []}`), "vuln.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseGovulncheck_InvalidJSON(t *testing.T) {
	_, err := ParseGovulncheck([]byte(`not json`), "vuln.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
