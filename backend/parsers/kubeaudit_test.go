package parsers

import (
	"testing"
)

func TestParseKubeaudit(t *testing.T) {
	data := []byte(`{
  "kubeaudit": [
    {
      "auditResult": {
        "levelname": "WARNING",
        "msg": "Container does not have a read-only root filesystem",
        "resource": {
          "name": "nginx",
          "namespace": "default",
          "kind": "Deployment",
          "apiversion": "apps/v1"
        },
        "metadata": {
          "container": "nginx"
        }
      }
    }
  ]
}`)

	findings, err := ParseKubeaudit(data, "kubeaudit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != "medium" {
		t.Errorf("expected warning -> medium, got %s", f.Severity)
	}
	if f.FilePath != "/nginx" {
		t.Errorf("expected /nginx, got %s", f.FilePath)
	}
}

func TestParseKubeaudit_Empty(t *testing.T) {
	findings, err := ParseKubeaudit([]byte(`{"kubeaudit": []}`), "kubeaudit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseKubeaudit_InvalidJSON(t *testing.T) {
	_, err := ParseKubeaudit([]byte(`not json`), "kubeaudit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
