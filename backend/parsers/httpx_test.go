package parsers

import (
	"testing"
)

func TestParseHttpx(t *testing.T) {
	data := []byte(`[{"url":"https://example.com","status_code":200,"title":"Example Domain","tech":["Apache","PHP"],"webserver":"Apache/2.4.41"}]`)

	findings, err := ParseHttpx(data, "httpx.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Title != "Example Domain" {
		t.Errorf("expected Example Domain, got %s", f.Title)
	}
	if f.Severity != "info" {
		t.Errorf("expected info, got %s", f.Severity)
	}
}

func TestParseHttpx_Empty(t *testing.T) {
	findings, err := ParseHttpx([]byte(`[]`), "httpx.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseHttpx_InvalidJSON(t *testing.T) {
	_, err := ParseHttpx([]byte(`not json`), "httpx.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
