package parsers

import (
	"testing"
)

func TestParseDockle(t *testing.T) {
	data := []byte(`{
  "results": [
    {
      "code": "CIS-DI-0001",
      "title": "Passwd file permissions are not 0644",
      "level": "FATAL",
      "alerts": ["0001"],
      "severity": "HIGH",
      "details": "A last user was found",
      "code_url": "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0001"
    }
  ]
}`)

	findings, err := ParseDockle(data, "dockle.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CIS-DI-0001" {
		t.Errorf("expected CIS-DI-0001, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.Title != "Passwd file permissions are not 0644" {
		t.Errorf("unexpected title: %s", f.Title)
	}
}

func TestParseDockle_Empty(t *testing.T) {
	findings, err := ParseDockle([]byte(`{"results": []}`), "dockle.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseDockle_InvalidJSON(t *testing.T) {
	_, err := ParseDockle([]byte(`not json`), "dockle.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
