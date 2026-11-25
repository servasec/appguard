package parsers

import (
	"testing"
)

func TestParseCfnNag(t *testing.T) {
	data := []byte(`{
  "messages": [
    {
      "type": "VIOLATION",
      "level": "ERROR",
      "id": "F1000",
      "message": "Security group ingress CIDR 0.0.0.0/0 is open to the world",
      "logicalResourceId": "PublicSG",
      "filepath": "template.yaml",
      "lineNumber": 8
    },
    {
      "type": "WARNING",
      "level": "WARN",
      "id": "W2",
      "message": "Security group has an egress rule allowing all destinations",
      "logicalResourceId": "PublicSG",
      "filepath": "template.yaml",
      "lineNumber": 12
    }
  ]
}`)

	findings, err := ParseCfnNag(data, "cfn-nag.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.RuleID != "F1000" {
		t.Errorf("expected F1000, got %s", f1.RuleID)
	}
	if f1.Severity != "high" {
		t.Errorf("expected high, got %s", f1.Severity)
	}
	if f1.FilePath != "/template.yaml" {
		t.Errorf("expected /template.yaml, got %s", f1.FilePath)
	}
	if f1.LineStart == nil || *f1.LineStart != 8 {
		t.Errorf("expected line 8, got %v", f1.LineStart)
	}

	f2 := findings[1]
	if f2.Severity != "medium" {
		t.Errorf("expected medium, got %s", f2.Severity)
	}
}

func TestParseCfnNag_Empty(t *testing.T) {
	findings, err := ParseCfnNag([]byte(`{"messages": []}`), "cfn-nag.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseCfnNag_InvalidJSON(t *testing.T) {
	_, err := ParseCfnNag([]byte(`not json`), "cfn-nag.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
