package parsers

import (
	"testing"
)

func TestParseTrivyOperator(t *testing.T) {
	data := []byte(`{
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "kind": "VulnerabilityReport",
  "metadata": {"name": "nginx", "namespace": "default"},
  "spec": {
    "results": [
      {
        "Target": "nginx:1.25",
        "Class": "os-pkgs",
        "Vulnerabilities": [
          {
            "VulnerabilityID": "CVE-2024-1234",
            "PkgName": "openssl",
            "Severity": "HIGH",
            "Title": "OpenSSL vulnerability",
            "Description": "A vulnerability in OpenSSL",
            "InstalledVersion": "1.1.1",
            "FixedVersion": "1.1.2",
            "PrimaryURL": "https://example.com/cve"
          }
        ]
      }
    ]
  }
}`)

	findings, err := ParseTrivyOperator(data, "trivy-operator.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high, got %s", f.Severity)
	}
	if f.FilePath != "nginx:1.25" {
		t.Errorf("expected nginx:1.25, got %s", f.FilePath)
	}
	if f.Remediation != "Upgrade openssl to version 1.1.2" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParseTrivyOperator_Empty(t *testing.T) {
	findings, err := ParseTrivyOperator([]byte(`{"spec": {"results": []}}`), "trivy-operator.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTrivyOperator_InvalidJSON(t *testing.T) {
	_, err := ParseTrivyOperator([]byte(`not json`), "trivy-operator.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
