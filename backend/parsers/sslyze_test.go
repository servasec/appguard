package parsers

import (
	"testing"
)

func TestParseSslyze(t *testing.T) {
	data := []byte(`{
  "sslyze_version": "5.1.0",
  "target": {"hostname": "example.com", "ip_address": "93.184.216.34"},
  "commands_results": {
    "heartbleed": {"result": "VULNERABLE - the server is vulnerable to the Heartbleed bug"},
    "compression": {"result": "NOT_VULNERABLE"},
    "renegotiation": {"result": "OK"}
  }
}`)

	findings, err := ParseSslyze(data, "sslyze.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SSLYZE-HEARTBLEED" {
		t.Errorf("expected SSLYZE-HEARTBLEED, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
	if f.FilePath != "example.com" {
		t.Errorf("expected example.com, got %s", f.FilePath)
	}
}

func TestParseSslyze_Empty(t *testing.T) {
	findings, err := ParseSslyze([]byte(`{"target": {"hostname": "example.com"}, "commands_results": {}}`), "sslyze.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseSslyze_InvalidJSON(t *testing.T) {
	_, err := ParseSslyze([]byte(`not json`), "sslyze.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
