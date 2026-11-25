package parsers

import (
	"testing"
)

func TestParseComposerAudit(t *testing.T) {
	data := []byte(`{
  "advisories": {
    "symfony/symfony": [
      {
        "advisoryId": "CVE-2020-15094",
        "packageName": "symfony/symfony",
        "title": "CVE-2020-15094: Caching of sensitive headers",
        "cve": "CVE-2020-15094",
        "link": "https://github.com/symfony/symfony/security/advisories",
        "affectedVersions": ">=3.2,<3.4.44"
      }
    ]
  },
  "verified": false
}`)

	findings, err := ParseComposerAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2020-15094" {
		t.Errorf("expected CVE-2020-15094, got %s", f.RuleID)
	}
	if f.FilePath != "symfony/symfony" {
		t.Errorf("expected symfony/symfony, got %s", f.FilePath)
	}
	if f.Remediation == "" {
		t.Error("expected remediation to be set")
	}
}

func TestParseComposerAudit_Empty(t *testing.T) {
	findings, err := ParseComposerAudit([]byte(`{"advisories": {}}`), "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseComposerAudit_InvalidJSON(t *testing.T) {
	_, err := ParseComposerAudit([]byte(`not json`), "audit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
