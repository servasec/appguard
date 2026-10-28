package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	URL         string `json:"url"`
	ContentType string `json:"content-type"`
}

func ParseFfuf(data []byte, filename string) ([]FindingInput, error) {
	var output ffufOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid ffuf JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Results {
		severity := "info"

		title := r.URL
		if title == "" {
			title = fmt.Sprintf("ffuf finding (status %d)", r.Status)
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.URL
		if filePath == "" {
			filePath = "/"
		} else if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := fmt.Sprintf("Status: %d, Length: %d", r.Status, r.Length)
		if r.ContentType != "" {
			description = fmt.Sprintf("%s, Content-Type: %s", description, r.ContentType)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      fmt.Sprintf("ffuf-%d", r.Status),
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
