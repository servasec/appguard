package parsers

import (
	"testing"
)

func TestParseNikto(t *testing.T) {
	data := []byte(`{
  "host": "192.168.1.10",
  "ip": "192.168.1.10",
  "port": "80",
  "vulnerabilities": [
    {
      "id": "0068",
      "OSVDB": "3092",
      "method": "GET",
      "url": "/admin/",
      "msg": "Admin directory found"
    }
  ]
}`)

	findings, err := ParseNikto(data, "nikto.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "OSVDB-3092" {
		t.Errorf("expected OSVDB-3092, got %s", f.RuleID)
	}
	if f.FilePath != "/admin/" {
		t.Errorf("expected /admin/, got %s", f.FilePath)
	}
}

func TestParseNikto_Empty(t *testing.T) {
	findings, err := ParseNikto([]byte(`{"host":"1.2.3.4","vulnerabilities":[]}`), "nikto.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseNikto_InvalidJSON(t *testing.T) {
	_, err := ParseNikto([]byte(`not json`), "nikto.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
