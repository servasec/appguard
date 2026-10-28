package parsers

import (
	"testing"
)

func TestParseFlawfinder(t *testing.T) {
	data := []byte(`{
  "error": "",
  "data": [
    {
      "category": "buffer",
      "coordinates": "src/main.c:50",
      "confidence": "HIGH",
      "file": "src/main.c",
      "line_number": 50,
      "message": "Function strcpy() with unbounded copy"
    }
  ]
}`)

	findings, err := ParseFlawfinder(data, "flaw.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.RuleID != "src/main.c:50" {
		t.Errorf("expected src/main.c:50, got %s", f.RuleID)
	}
	if f.FilePath != "/src/main.c" {
		t.Errorf("expected /src/main.c, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 50 {
		t.Errorf("expected line 50, got %v", f.LineStart)
	}
}

func TestParseFlawfinder_Empty(t *testing.T) {
	findings, err := ParseFlawfinder([]byte(`{"data": []}`), "flaw.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseFlawfinder_InvalidJSON(t *testing.T) {
	_, err := ParseFlawfinder([]byte(`not json`), "flaw.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
