package parsers

import (
	"testing"
)

func TestParsePopeye(t *testing.T) {
	data := []byte(`{
  "popeye": {
    "name": "popeye",
    "sanitized": {
      "code": [
        "default/test-deployment: Deployment has no pod security policy",
        "critical/nginx: Container uses an untrusted image"
      ]
    }
  }
}`)

	findings, err := ParsePopeye(data, "popeye.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.Severity != "medium" {
		t.Errorf("expected medium, got %s", f1.Severity)
	}

	f2 := findings[1]
	if f2.Severity != "high" {
		t.Errorf("expected high, got %s", f2.Severity)
	}
}

func TestParsePopeye_Empty(t *testing.T) {
	findings, err := ParsePopeye([]byte(`{"popeye": {"sanitized": {"code": []}}}`), "popeye.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParsePopeye_InvalidJSON(t *testing.T) {
	_, err := ParsePopeye([]byte(`not json`), "popeye.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
