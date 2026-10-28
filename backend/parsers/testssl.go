package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type testsslOutput []testsslResult

type testsslResult struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
}

func ParseTestssl(data []byte, filename string) ([]FindingInput, error) {
	var output testsslOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid testssl JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output {
		severity := strings.ToLower(r.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		if strings.Contains(strings.ToUpper(r.Finding), "NOT") && strings.Contains(strings.ToUpper(r.Finding), "VULNERABLE") {
			continue
		}
		if strings.Contains(strings.ToUpper(r.Finding), "OK") {
			continue
		}

		title := r.ID
		if title == "" {
			title = "testssl finding"
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.ID
		if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := r.Finding
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      r.ID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
