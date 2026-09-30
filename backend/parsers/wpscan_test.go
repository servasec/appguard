package parsers

import (
	"testing"
)

func TestParseWpscan(t *testing.T) {
	data := []byte(`{
  "vulns": {
    "12345": {
      "title": "WordPress < 5.8 - XSS",
      "severity": "high",
      "fix_version": "5.8"
    }
  }
}`)

	findings, err := ParseWpscan(data, "wpscan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "12345" {
		t.Errorf("expected 12345, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.Remediation != "Upgrade to version 5.8" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParseWpscan_Empty(t *testing.T) {
	findings, err := ParseWpscan([]byte(`{"vulns": {}}`), "wpscan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseWpscan_InvalidJSON(t *testing.T) {
	_, err := ParseWpscan([]byte(`not json`), "wpscan.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
