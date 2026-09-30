package parsers

import (
	"testing"
)

func TestParseHorusec(t *testing.T) {
	data := []byte(`{
  "analysisVulnerabilities": [
    {
      "vulnerabilities": [
        {
          "ruleID": "HS-JAVA-0001",
          "line": 22,
          "column": 5,
          "confidence": "HIGH",
          "file": "src/main/java/App.java",
          "code": "System.out.println(input);",
          "details": "Reflected XSS possible",
          "severity": "HIGH"
        }
      ],
      "analysisStatus": "Success"
    }
  ]
}`)

	findings, err := ParseHorusec(data, "horusec.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "HS-JAVA-0001" {
		t.Errorf("expected HS-JAVA-0001, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "/src/main/java/App.java" {
		t.Errorf("expected /src/main/java/App.java, got %s", f.FilePath)
	}
	if f.LineStart == nil || *f.LineStart != 22 {
		t.Errorf("expected line 22, got %v", f.LineStart)
	}
}

func TestParseHorusec_Empty(t *testing.T) {
	findings, err := ParseHorusec([]byte(`{"analysisVulnerabilities": []}`), "horusec.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseHorusec_InvalidJSON(t *testing.T) {
	_, err := ParseHorusec([]byte(`not json`), "horusec.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
