package parsers

import (
	"testing"
)

func TestParseNaabu(t *testing.T) {
	data := []byte(`[{"host":"example.com","ip":"93.184.216.34","port":80,"protocol":"tcp"}]`)

	findings, err := ParseNaabu(data, "naabu.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "naabu-port-80" {
		t.Errorf("expected naabu-port-80, got %s", f.RuleID)
	}
	if f.Severity != "info" {
		t.Errorf("expected info, got %s", f.Severity)
	}
	if f.FilePath != "/80/tcp" {
		t.Errorf("expected /80/tcp, got %s", f.FilePath)
	}
}

func TestParseNaabu_Empty(t *testing.T) {
	findings, err := ParseNaabu([]byte(`[]`), "naabu.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseNaabu_InvalidJSON(t *testing.T) {
	_, err := ParseNaabu([]byte(`not json`), "naabu.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
