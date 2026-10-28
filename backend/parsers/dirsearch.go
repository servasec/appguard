package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type dirsearchOutput struct {
	Results []dirsearchResult `json:"results"`
}

type dirsearchResult struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int    `json:"content-length"`
	Redirect      string `json:"redirect"`
}

func ParseDirsearch(data []byte, filename string) ([]FindingInput, error) {
	var output dirsearchOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid dirsearch JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Results {
		severity := "info"

		title := r.URL
		if title == "" {
			title = fmt.Sprintf("dirsearch finding (status %d)", r.Status)
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

		description := fmt.Sprintf("Status: %d, Length: %d", r.Status, r.ContentLength)
		if r.Redirect != "" {
			description = fmt.Sprintf("%s, Redirect: %s", description, r.Redirect)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      fmt.Sprintf("dirsearch-%d", r.Status),
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
