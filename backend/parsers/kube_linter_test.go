package parsers

import (
	"testing"
)

func TestParseKubeLinter(t *testing.T) {
	data := []byte(`{
  "results": [
    {
      "diagnosticMessage": "[no-read-only-root-fs] Container nginx in Pod default/nginx-pod does not have a read-only root filesystem",
      "object": {
        "filePath": "deployment.yaml"
      }
    }
  ]
}`)

	findings, err := ParseKubeLinter(data, "lint.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "no-read-only-root-fs" {
		t.Errorf("expected no-read-only-root-fs, got %s", f.RuleID)
	}
	if f.FilePath != "/deployment.yaml" {
		t.Errorf("expected /deployment.yaml, got %s", f.FilePath)
	}
}

func TestParseKubeLinter_Empty(t *testing.T) {
	findings, err := ParseKubeLinter([]byte(`{"results": []}`), "lint.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseKubeLinter_InvalidJSON(t *testing.T) {
	_, err := ParseKubeLinter([]byte(`not json`), "lint.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
