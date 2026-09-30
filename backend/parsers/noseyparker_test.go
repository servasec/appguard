package parsers

import (
	"testing"
)

func TestParseNoseyparker(t *testing.T) {
	data := []byte(`{
  "metadata": {
    "version": "0.18.0",
    "workspace": "/repo"
  },
  "matches": [
    {
      "rule": "private-key",
      "name": "Private Key",
      "path": "keys/app.pem",
      "matchedContent": "-----BEGIN PRIVATE KEY-----",
      "source_span": {
        "start": {"line": 1, "column": 1, "offset": 0}
      }
    }
  ]
}`)

	findings, err := ParseNoseyparker(data, "noseyparker.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "private-key" {
		t.Errorf("expected private-key, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "/keys/app.pem" {
		t.Errorf("expected /keys/app.pem, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 1 {
		t.Errorf("expected line 1, got %v", f.LineStart)
	}
}

func TestParseNoseyparker_Empty(t *testing.T) {
	findings, err := ParseNoseyparker([]byte(`{"metadata": {}, "matches": []}`), "noseyparker.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseNoseyparker_InvalidJSON(t *testing.T) {
	_, err := ParseNoseyparker([]byte(`not json`), "noseyparker.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
