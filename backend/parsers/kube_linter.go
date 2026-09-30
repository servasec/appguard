package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type kubeLinterOutput struct {
	Results []kubeLinterResult `json:"results"`
}

type kubeLinterResult struct {
	DiagnosticMessage string `json:"diagnosticMessage"`
	Object            struct {
		FilePath string `json:"filePath"`
	} `json:"object"`
}

func ParseKubeLinter(data []byte, filename string) ([]FindingInput, error) {
	var output kubeLinterOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid kube-linter JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Results {
		severity := "medium"

		title := r.DiagnosticMessage
		if title == "" {
			title = "kube-linter finding"
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.Object.FilePath
		if filePath == "" {
			filePath = "/"
		} else if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := r.DiagnosticMessage
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		ruleID := ""
		if strings.Contains(r.DiagnosticMessage, "[") && strings.Contains(r.DiagnosticMessage, "]") {
			start := strings.Index(r.DiagnosticMessage, "[")
			end := strings.Index(r.DiagnosticMessage, "]")
			if start < end {
				ruleID = r.DiagnosticMessage[start+1 : end]
			}
		}
		if ruleID == "" {
			ruleID = "kube-linter"
		}

		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
