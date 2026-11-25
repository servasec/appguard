package parsers

import (
	"testing"
)

func TestParseTestssl(t *testing.T) {
	data := []byte(`[
  {"id": "heartbleed", "severity": "CRITICAL", "finding": "NOT vulnerable"},
  {"id": "ssl_poodle", "severity": "HIGH", "finding": "VULNERABLE - the server is vulnerable to POODLE"},
  {"id": "cert_trust", "severity": "LOW", "finding": "NOT ok"}
]`)

	findings, err := ParseTestssl(data, "testssl.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (vulnerable or not-ok only), got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "ssl_poodle" {
		t.Errorf("expected ssl_poodle, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
}

func TestParseTestssl_Empty(t *testing.T) {
	findings, err := ParseTestssl([]byte(`[]`), "testssl.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTestssl_InvalidJSON(t *testing.T) {
	_, err := ParseTestssl([]byte(`not json`), "testssl.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
