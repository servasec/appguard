package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// cppcheck --template="{json_template}" emits one JSON object per line (JSONL).
type cppcheckFinding struct {
	Tool     string `json:"tool"`
	Check    string `json:"check"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	CWE      string `json:"cwe"`
	Verbose  string `json:"verbose"`
}

func ParseCppcheck(data []byte, filename string) ([]FindingInput, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty cppcheck input")
	}

	var findings []FindingInput
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		var f cppcheckFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return nil, fmt.Errorf("invalid cppcheck JSON on line %d: %w", lineNum, err)
		}

		severity := "medium"
		switch strings.ToLower(f.Severity) {
		case "error":
			severity = "high"
		case "warning":
			severity = "medium"
		case "style", "performance", "portability", "information":
			severity = "low"
		}

		title := f.Message
		if title == "" {
			title = "cppcheck finding"
		}
		if len(title) > 500 {
			title = title[:500]
		}

		ruleID := f.Check
		if ruleID == "" {
			ruleID = "cppcheck"
		}

		filePath := f.File
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if f.Line > 0 {
			lineStart = &f.Line
		}

		description := f.Verbose
		if description == "" {
			description = f.Message
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		cweID := ""
		if f.CWE != "" {
			upper := strings.ToUpper(f.CWE)
			if strings.HasPrefix(upper, "CWE-") {
				cweID = upper
			}
		}

		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			LineStart:   lineStart,
			CWEID:       cweID,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading cppcheck input: %w", err)
	}

	return findings, nil
}
