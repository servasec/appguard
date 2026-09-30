package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type dockleOutput struct {
	Results []dockleResult `json:"results"`
}

type dockleResult struct {
	Code     string `json:"code"`
	Title    string `json:"title"`
	Details  string `json:"details"`
	Severity string `json:"severity"`
	CodeURL  string `json:"code_url"`
}

func ParseDockle(data []byte, filename string) ([]FindingInput, error) {
	var output dockleOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid dockle JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Results {
		severity := strings.ToLower(r.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := r.Title
		if title == "" {
			title = r.Code
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.Code
		if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := r.Details
		if description == "" {
			description = r.Title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      r.Code,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
