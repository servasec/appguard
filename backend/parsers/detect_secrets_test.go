package parsers

import (
	"testing"
)

func TestParseDetectSecrets(t *testing.T) {
	data := []byte(`{
  "results": {
    "app/config.py": [
      {
        "type": "Secret Keyword",
        "line_number": 42,
        "details": "SecretKeyword Detected"
      }
    ],
    "app/.env": [
      {
        "type": "Hex High Entropy String",
        "line_number": 3,
        "details": "HexHighEntropyString Detected"
      }
    ]
  }
}`)

	findings, err := ParseDetectSecrets(data, "secrets.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	var f1 *FindingInput
	for i := range findings {
		if findings[i].FilePath == "/app/config.py" {
			f1 = &findings[i]
			break
		}
	}
	if f1 == nil {
		t.Fatal("expected a finding for /app/config.py")
	}
	if f1.RuleID != "Secret Keyword" {
		t.Errorf("expected Secret Keyword, got %s", f1.RuleID)
	}
	if f1.LineStart == nil || *f1.LineStart != 42 {
		t.Errorf("expected line 42, got %v", f1.LineStart)
	}
}

func TestParseDetectSecrets_Empty(t *testing.T) {
	findings, err := ParseDetectSecrets([]byte(`{"results": {}}`), "secrets.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseDetectSecrets_InvalidJSON(t *testing.T) {
	_, err := ParseDetectSecrets([]byte(`not json`), "secrets.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
