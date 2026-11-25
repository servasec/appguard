package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type njsscanOutput struct {
	Files map[string][]njsscanFinding `json:"files"`
}

type njsscanFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Hash        string `json:"hash"`
	Line        int    `json:"line"`
	Metadata    struct {
		Severity string `json:"severity"`
		CWE      string `json:"cwe"`
		OWASP    string `json:"owasp"`
	} `json:"metadata"`
}

func ParseNjsscan(data []byte, filename string) ([]FindingInput, error) {
	var output njsscanOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid njsscan JSON: %w", err)
	}

	var findings []FindingInput
	for file, findingsList := range output.Files {
		for _, f := range findingsList {
			severity := strings.ToLower(f.Metadata.Severity)
			if err := validateSeverity(severity); err != nil {
				severity = "medium"
			}

			title := f.Title
			if title == "" {
				title = severity
			}
			if len(title) > 500 {
				title = title[:500]
			}

			ruleID := f.Hash
			if ruleID == "" {
				ruleID = f.Title
			}

			filePath := file
			if filePath != "" && !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			var lineStart *int
			if f.Line > 0 {
				lineStart = &f.Line
			}

			description := f.Description
			if description == "" {
				description = f.Title
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			cweID := ""
			if f.Metadata.CWE != "" {
				if strings.HasPrefix(f.Metadata.CWE, "CWE-") {
					cweID = f.Metadata.CWE
				} else {
					cweID = "CWE-" + f.Metadata.CWE
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
	}

	return findings, nil
}
