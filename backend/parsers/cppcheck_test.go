package parsers

import (
	"testing"
)

func TestParseCppcheck(t *testing.T) {
	data := []byte(`{"tool":"Cppcheck","check":"uninitvar","file":"src/main.c","line":42,"column":3,"severity":"error","message":"Uninitialized variable: buf","cwe":"cwe-457","verbose":"Uninitialized variable: buf"}
{"tool":"Cppcheck","check":"missingIncludeSystem","file":"src/helper.c","line":7,"column":0,"severity":"information","message":"Include file not found","cwe":"","verbose":"Various files not found"}
`)

	findings, err := ParseCppcheck(data, "cppcheck.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.RuleID != "uninitvar" {
		t.Errorf("expected uninitvar, got %s", f1.RuleID)
	}
	if f1.Severity != "high" {
		t.Errorf("expected high, got %s", f1.Severity)
	}
	if f1.CWEID != "CWE-457" {
		t.Errorf("expected CWE-457, got %s", f1.CWEID)
	}
	if f1.FilePath != "/src/main.c" {
		t.Errorf("expected /src/main.c, got %s", f1.FilePath)
	}
	if f1.LineStart == nil || *f1.LineStart != 42 {
		t.Errorf("expected line 42, got %v", f1.LineStart)
	}

	f2 := findings[1]
	if f2.Severity != "low" {
		t.Errorf("expected low, got %s", f2.Severity)
	}
}

func TestParseCppcheck_EmptyInput(t *testing.T) {
	// Whitespace-only input is treated as empty, matching nuclei convention.
	if _, err := ParseCppcheck([]byte("   \n  "), "cppcheck.json"); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseCppcheck_InvalidJSON(t *testing.T) {
	_, err := ParseCppcheck([]byte(`not json`), "cppcheck.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
