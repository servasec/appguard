package parsers

import (
	"testing"
)

func TestParseTerrascan(t *testing.T) {
	data := []byte(`{
  "results": {
    "violations": [
      {
        "rule_name": "S3BucketPublicAccess",
        "rule_id": "AC-AWS-0157",
        "severity": "HIGH",
        "category": "Security",
        "resource_name": "aws_s3_bucket.example",
        "resource_type": "aws_s3_bucket",
        "file": "main.tf",
        "line": 10
      }
    ]
  }
}`)

	findings, err := ParseTerrascan(data, "scan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "AC-AWS-0157" {
		t.Errorf("expected AC-AWS-0157, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "/main.tf" {
		t.Errorf("expected /main.tf, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 10 {
		t.Errorf("expected line 10, got %v", f.LineStart)
	}
}

func TestParseTerrascan_Empty(t *testing.T) {
	findings, err := ParseTerrascan([]byte(`{"results": {"violations": []}}`), "scan.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTerrascan_InvalidJSON(t *testing.T) {
	_, err := ParseTerrascan([]byte(`not json`), "scan.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
