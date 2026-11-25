package parsers

import (
	"testing"
)

func TestParseDirsearch(t *testing.T) {
	data := []byte(`{
  "results": [
    {"url": "https://example.com/admin", "status": 200, "content-length": 1234},
    {"url": "https://example.com/config.php.bak", "status": 200, "content-length": 987, "redirect": "https://example.com/config.php"}
  ]
}`)

	findings, err := ParseDirsearch(data, "dirsearch.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "dirsearch-200" {
		t.Errorf("expected dirsearch-200, got %s", f.RuleID)
	}
	if f.FilePath != "/https://example.com/admin" {
		t.Errorf("expected /https://example.com/admin, got %s", f.FilePath)
	}
}

func TestParseDirsearch_Empty(t *testing.T) {
	findings, err := ParseDirsearch([]byte(`{"results": []}`), "dirsearch.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseDirsearch_InvalidJSON(t *testing.T) {
	_, err := ParseDirsearch([]byte(`not json`), "dirsearch.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
