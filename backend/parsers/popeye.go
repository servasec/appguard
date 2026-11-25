package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type popeyeOutput struct {
	Popeye struct {
		Sanitized struct {
			Code []string `json:"code"`
		} `json:"sanitized"`
	} `json:"popeye"`
}

func ParsePopeye(data []byte, filename string) ([]FindingInput, error) {
	var output popeyeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid popeye JSON: %w", err)
	}

	var findings []FindingInput
	for _, c := range output.Popeye.Sanitized.Code {
		severity := "medium"
		lower := strings.ToLower(c)
		if strings.Contains(lower, "error") || strings.Contains(lower, "critical") {
			severity = "high"
		} else if strings.Contains(lower, "info") || strings.Contains(lower, "warning") {
			severity = "low"
		}

		title := c
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := "/"
		parts := strings.Fields(c)
		if len(parts) > 0 {
			namespace := parts[0]
			filePath = "/" + namespace
			if !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}
		}

		findings = append(findings, FindingInput{
			RuleID:      "POPEYE",
			Title:       title,
			Severity:    severity,
			Description: c,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
