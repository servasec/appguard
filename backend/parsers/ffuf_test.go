package parsers

import (
	"testing"
)

func TestParseFfuf(t *testing.T) {
	data := []byte(`{
  "commandline": "ffuf -w wordlist.txt -u https://example.com/FUZZ -of json",
  "results": [
    {"status": 200, "length": 1234, "url": "https://example.com/admin", "content-type": "text/html"},
    {"status": 403, "length": 312, "url": "https://example.com/private", "content-type": "text/html"}
  ]
}`)

	findings, err := ParseFfuf(data, "ffuf.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "ffuf-200" {
		t.Errorf("expected ffuf-200, got %s", f.RuleID)
	}
	if f.FilePath != "/https://example.com/admin" {
		t.Errorf("expected /https://example.com/admin, got %s", f.FilePath)
	}
}

func TestParseFfuf_Empty(t *testing.T) {
	findings, err := ParseFfuf([]byte(`{"results": []}`), "ffuf.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseFfuf_InvalidJSON(t *testing.T) {
	_, err := ParseFfuf([]byte(`not json`), "ffuf.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
