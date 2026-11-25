package parsers

import (
	"strings"
	"testing"
)

func TestParseProwler(t *testing.T) {
	data := []byte(`{
  "findings": [
    {
      "checkId": "iam_user_mfa_enabled",
      "status": "FAIL",
      "message": "User has no MFA enabled",
      "severity": "high",
      "region": "us-east-1",
      "resourceName": "arn:aws:iam::123456789012:user/admin",
      "description": "Ensure user has MFA"
    },
    {
      "checkId": "s3_bucket_public",
      "status": "PASS",
      "message": "Bucket is private",
      "severity": "low"
    }
  ]
}`)

	findings, err := ParseProwler(data, "prowler.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (FAIL only), got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "iam_user_mfa_enabled" {
		t.Errorf("expected iam_user_mfa_enabled, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "us-east-1") {
		t.Errorf("expected region in description, got %s", f.Description)
	}
}

func TestParseProwler_Empty(t *testing.T) {
	findings, err := ParseProwler([]byte(`{"findings": []}`), "prowler.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseProwler_InvalidJSON(t *testing.T) {
	_, err := ParseProwler([]byte(`not json`), "prowler.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
