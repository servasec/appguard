package parsers

import (
	"testing"
)

func TestParseNmap(t *testing.T) {
	data := []byte(`{
  "nmaprun": {
    "host": [
      {
        "ports": {
          "port": [
            {
              "protocol": "tcp",
              "portid": "22",
              "state": {"state": "open"},
              "service": {"name": "ssh", "product": "OpenSSH", "version": "8.2"}
            },
            {
              "protocol": "tcp",
              "portid": "80",
              "state": {"state": "closed"},
              "service": {"name": "http"}
            }
          ]
        }
      }
    ]
  }
}`)

	findings, err := ParseNmap(data, "nmap.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (open port only), got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "port-22/tcp" {
		t.Errorf("expected port-22/tcp, got %s", f.RuleID)
	}
	if f.Severity != "info" {
		t.Errorf("expected info, got %s", f.Severity)
	}
}

func TestParseNmap_Empty(t *testing.T) {
	findings, err := ParseNmap([]byte(`{"nmaprun": {"host": []}}`), "nmap.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseNmap_InvalidJSON(t *testing.T) {
	_, err := ParseNmap([]byte(`not json`), "nmap.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
