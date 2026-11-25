package parsers

import "testing"

func TestParseSemgrep(t *testing.T) {
	data := []byte(`{
  "results": [
    {
      "check_id": "python.lang.security.audit.dangerous-system-call",
      "path": "app.py",
      "start": {"line": 10},
      "end": {"line": 12},
      "extra": {
        "message": "Detected a system call that may allow command injection",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-78"],
          "technology": ["python"]
        },
        "lines": "subprocess.call(cmd, shell=True)"
      }
    },
    {
      "check_id": "python.lang.correctness.useless-eqeq",
      "path": "/src/auth.py",
      "start": {"line": 42},
      "end": {"line": 42},
      "extra": {
        "message": "useless comparison",
        "severity": "WARNING",
        "metadata": {
          "cwe": "CWE-398"
        }
      }
    }
  ],
  "errors": []
}`)

	findings, err := ParseSemgrep(data, "semgrep.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.RuleID != "python.lang.security.audit.dangerous-system-call" {
		t.Errorf("unexpected ruleID: %s", f1.RuleID)
	}
	if f1.Severity != "high" {
		t.Errorf("expected high (from ERROR), got %s", f1.Severity)
	}
	if f1.FilePath != "/app.py" {
		t.Errorf("expected /app.py, got %s", f1.FilePath)
	}
	if f1.LineStart == nil || *f1.LineStart != 10 {
		t.Errorf("expected line 10, got %v", f1.LineStart)
	}
	if f1.LineEnd == nil || *f1.LineEnd != 12 {
		t.Errorf("expected line 12, got %v", f1.LineEnd)
	}
	if f1.CWEID != "CWE-78" {
		t.Errorf("expected CWE-78, got %s", f1.CWEID)
	}
	if f1.Title != "Detected a system call that may allow command injection" {
		t.Errorf("unexpected title: %s", f1.Title)
	}

	f2 := findings[1]
	if f2.Severity != "medium" {
		t.Errorf("expected medium (from WARNING), got %s", f2.Severity)
	}
	if f2.CWEID != "CWE-398" {
		t.Errorf("expected CWE-398 (from string cwe), got %s", f2.CWEID)
	}
	if f2.FilePath != "/src/auth.py" {
		t.Errorf("expected /src/auth.py, got %s", f2.FilePath)
	}
}

func TestParseSemgrep_InfoSeverity(t *testing.T) {
	findings, err := ParseSemgrep([]byte(`{
  "results": [
    {
      "check_id": "python.lang.security.audit.eval-usage",
      "path": "src/eval.py",
      "start": {"line": 3},
      "end": {"line": 3},
      "extra": {
        "message": "Audit eval usage",
        "severity": "INFO",
        "metadata": {"cwe": ["CWE-95"]}
      }
    }
  ]
}`), "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "low" {
		t.Errorf("expected low (from INFO), got %s", findings[0].Severity)
	}
	if findings[0].CWEID != "CWE-95" {
		t.Errorf("expected CWE-95, got %s", findings[0].CWEID)
	}
}

func TestParseSemgrep_EmptyMessageTitleFallback(t *testing.T) {
	findings, err := ParseSemgrep([]byte(`{
  "results": [
    {
      "check_id": "python.lang.correctness.identity-comparison",
      "path": "app.py",
      "start": {"line": 1},
      "end": {"line": 1},
      "extra": {"severity": "ERROR", "metadata": {}}
    }
  ]
}`), "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "python.lang.correctness.identity-comparison" {
		t.Errorf("expected fallback to check_id, got %s", findings[0].Title)
	}
	if findings[0].CWEID != "" {
		t.Errorf("expected empty CWEID, got %s", findings[0].CWEID)
	}
}

func TestParseSemgrep_LongMessageTruncated(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	data := []byte(`{
  "results": [
    {
      "check_id": "cwe-79",
      "path": "app.py",
      "start": {"line": 1},
      "end": {"line": 1},
      "extra": {"message": "` + string(long) + `", "severity": "WARNING", "metadata": {}}
    }
  ]
}`)

	findings, err := ParseSemgrep(data, "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].Title) > 500 {
		t.Errorf("expected title truncated to 500, got %d", len(findings[0].Title))
	}
}

func TestParseSemgrep_Empty(t *testing.T) {
	findings, err := ParseSemgrep([]byte(`{"results": []}`), "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseSemgrep_InvalidJSON(t *testing.T) {
	_, err := ParseSemgrep([]byte(`not json`), "test.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseSemgrep_AlwaysNonNilLines(t *testing.T) {
	findings, err := ParseSemgrep([]byte(`{
  "results": [
    {
      "check_id": "r1",
      "path": "app.py",
      "start": {"line": 0},
      "end": {"line": 0},
      "extra": {"severity": "ERROR", "metadata": {}}
    }
  ]
}`), "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].LineStart == nil {
		t.Error("expected non-nil LineStart even for zero line")
	}
	if findings[0].LineEnd == nil {
		t.Error("expected non-nil LineEnd even for zero line")
	}
}

func TestExtractCWE(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"string form", `"CWE-78"`, "CWE-78"},
		{"array form", `["CWE-79","CWE-80"]`, "CWE-79"},
		{"empty array", `[]`, ""},
		{"number form", `79`, ""},
		{"null", `null`, ""},
		{"absent", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCWE([]byte(tt.raw))
			if got != tt.want {
				t.Errorf("extractCWE(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestDetectScannerType_Semgrep(t *testing.T) {
	data := []byte(`{"results": [{"check_id": "foo", "path": "a.py"}]}`)
	if got := DetectScannerType(data); got != "semgrep" {
		t.Errorf("expected semgrep, got %s", got)
	}
}

func TestDetectScannerType_SemgrepArray(t *testing.T) {
	data := []byte(`[{"check_id": "foo", "path": "a.py"}]`)
	if got := DetectScannerType(data); got != "semgrep" {
		t.Errorf("expected semgrep (array), got %s", got)
	}
}
