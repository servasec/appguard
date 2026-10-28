package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type prowlerOutput struct {
	Findings []prowlerFinding `json:"findings"`
}

type prowlerFinding struct {
	CheckID      string `json:"checkId"`
	Status       string `json:"status"`
	Message      string `json:"message"`
	Severity     string `json:"severity"`
	Region       string `json:"region"`
	ResourceName string `json:"resourceName"`
	Description  string `json:"description"`
}

func ParseProwler(data []byte, filename string) ([]FindingInput, error) {
	var output prowlerOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid prowler JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Findings {
		if strings.ToUpper(r.Status) == "PASS" || r.CheckID == "" {
			continue
		}

		severity := strings.ToLower(r.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := r.Message
		if title == "" {
			title = r.CheckID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := "/"
		if r.ResourceName != "" {
			filePath = "/" + r.ResourceName
			if !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}
		}

		description := r.Description
		if description == "" {
			description = r.Message
		}
		if r.Region != "" {
			description = fmt.Sprintf("[%s] %s", r.Region, description)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      r.CheckID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
