package parsers

import (
	"testing"
)

func TestParseDockerBenchSecurity(t *testing.T) {
	data := []byte(`[
  {
    "id": "1",
    "desc": "Host Configuration",
    "results": [
      {
        "test_number": "1.1",
        "test_desc": "Ensure a separate partition for containers has been created",
        "fail": true,
        "details": "Currently no partition for containers"
      },
      {
        "test_number": "1.2",
        "test_desc": "Ensure only trusted users are allowed to control Docker daemon",
        "fail": false,
        "details": ""
      }
    ]
  }
]`)

	findings, err := ParseDockerBenchSecurity(data, "bench.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "1.1" {
		t.Errorf("expected 1.1, got %s", f.RuleID)
	}
	if f.Title != "Ensure a separate partition for containers has been created" {
		t.Errorf("unexpected title: %s", f.Title)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
}

func TestParseDockerBenchSecurity_Empty(t *testing.T) {
	findings, err := ParseDockerBenchSecurity([]byte(`[]`), "bench.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseDockerBenchSecurity_InvalidJSON(t *testing.T) {
	_, err := ParseDockerBenchSecurity([]byte(`not json`), "bench.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
