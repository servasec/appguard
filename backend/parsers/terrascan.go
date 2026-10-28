package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type terrascanOutput struct {
	Results struct {
		Violations []terrascanViolation `json:"violations"`
	} `json:"results"`
}

type terrascanViolation struct {
	RuleName     string          `json:"rule_name"`
	RuleID       string          `json:"rule_id"`
	Severity     string          `json:"severity"`
	Category     string          `json:"category"`
	ResourceName string          `json:"resource_name"`
	ResourceType string          `json:"resource_type"`
	File         string          `json:"file"`
	LineNumber   json.RawMessage `json:"line"`
}

func ParseTerrascan(data []byte, filename string) ([]FindingInput, error) {
	var output terrascanOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid terrascan JSON: %w", err)
	}

	var findings []FindingInput
	for _, v := range output.Results.Violations {
		severity := strings.ToLower(v.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := v.RuleName
		if title == "" {
			title = v.RuleID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := v.File
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if len(v.LineNumber) > 0 {
			var n int
			if err := json.Unmarshal(v.LineNumber, &n); err == nil && n > 0 {
				lineStart = &n
			}
		}

		description := fmt.Sprintf("%s on %s (%s)", v.RuleName, v.ResourceName, v.ResourceType)
		if v.Category != "" {
			description = fmt.Sprintf("%s [%s]", description, v.Category)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      v.RuleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			LineStart:   lineStart,
		})
	}

	return findings, nil
}
