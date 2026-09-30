package parsers

import (
	"testing"
)

func TestParseYarnAudit(t *testing.T) {
	data := []byte(`{"type":"auditAdvisory","data":{"resolution":{"id":1179,"path":"minimist"},"advisory":{"findings":[{"version":"0.0.8","paths":["minimist"]}],"id":1179,"created":"2020-03-24T01:50:33.856Z","updated":"2023-06-21T20:26:12.863Z","deleted":null,"title":"Prototype Pollution in minimist","found_by":{"link":"","name":""},"reported_by":{"link":"","name":""},"module_name":"minimist","severity":"high","vulnerable_versions":"<0.2.1","patched_versions":">=0.2.1","recommendation":"Upgrade to version 0.2.1 or later","references":"","cves":["CVE-2020-7598"]}}}
{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0},"dependencies":118,"devDependencies":0,"optionalDependencies":0,"totalDependencies":118}}
`)

	findings, err := ParseYarnAudit(data, "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2020-7598" {
		t.Errorf("expected CVE-2020-7598, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "minimist@<0.2.1" {
		t.Errorf("expected minimist@<0.2.1, got %s", f.FilePath)
	}
	if f.Remediation != "Upgrade minimist to >=0.2.1" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParseYarnAudit_Empty(t *testing.T) {
	// Only auditSummary lines (no advisory) yield 0 findings without error.
	findings, err := ParseYarnAudit([]byte(`{"type":"auditSummary","data":{"vulnerabilities":{}}}
`), "audit.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseYarnAudit_EmptyInput(t *testing.T) {
	// Whitespace-only input is treated as empty, matching nuclei convention.
	if _, err := ParseYarnAudit([]byte("   \n  "), "audit.json"); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseYarnAudit_InvalidJSON(t *testing.T) {
	_, err := ParseYarnAudit([]byte(`not json`), "audit.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
