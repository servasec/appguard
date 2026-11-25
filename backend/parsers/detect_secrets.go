package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
)

type detectSecretsOutput struct {
	Results map[string][]detectSecretsResult `json:"results"`
}

type detectSecretsResult struct {
	Type       string `json:"type"`
	LineNumber int    `json:"line_number"`
	Details    string `json:"details"`
}

func ParseDetectSecrets(data []byte, filename string) ([]FindingInput, error) {
	var output detectSecretsOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid detect-secrets JSON: %w", err)
	}

	var findings []FindingInput
	files := make([]string, 0, len(output.Results))
	for file := range output.Results {
		files = append(files, file)
	}
	sort.Strings(files)

	for _, file := range files {
		for _, r := range output.Results[file] {
			severity := "medium"

			title := fmt.Sprintf("Secret detected: %s", r.Type)
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := file
			if filePath != "" && !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			var lineStart *int
			if r.LineNumber > 0 {
				lineStart = &r.LineNumber
			}

			description := r.Details
			if description == "" {
				description = title
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      r.Type,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
				LineStart:   lineStart,
			})
		}
	}

	return findings, nil
}
