package parsers

import (
	"testing"
)

func TestParseScoutsuite(t *testing.T) {
	data := []byte(`{
  "services": {
    "iam": {
      "findings": {
        "ROOT_USER_MFA_ENABLED": {
          "items": ["arn:aws:iam::123456789012:root"],
          "description": "Root user does not have MFA enabled",
          "rationale": "MFA adds an extra layer of protection",
          "risk": "HIGH"
        }
      }
    }
  }
}`)

	findings, err := ParseScoutsuite(data, "scoutsuite.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "ROOT_USER_MFA_ENABLED" {
		t.Errorf("expected ROOT_USER_MFA_ENABLED, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
}

func TestParseScoutsuite_Empty(t *testing.T) {
	findings, err := ParseScoutsuite([]byte(`{"services": {}}`), "scoutsuite.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseScoutsuite_InvalidJSON(t *testing.T) {
	_, err := ParseScoutsuite([]byte(`not json`), "scoutsuite.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
