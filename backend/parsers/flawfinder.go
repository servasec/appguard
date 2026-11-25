package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type flawfinderOutput struct {
	Data []flawfinderResult `json:"data"`
}

type flawfinderResult struct {
	Category    string `json:"category"`
	Coordinates string `json:"coordinates"`
	Confidence  string `json:"confidence"`
	File        string `json:"file"`
	LineNumber  int    `json:"line_number"`
	Message     string `json:"message"`
}

func ParseFlawfinder(data []byte, filename string) ([]FindingInput, error) {
	var output flawfinderOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid flawfinder JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Data {
		severity := "medium"
		switch strings.ToLower(r.Confidence) {
		case "high", "highest":
			severity = "high"
		case "medium":
			severity = "medium"
		case "low":
			severity = "low"
		}

		title := r.Message
		if title == "" {
			title = r.Category
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.File
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if r.LineNumber > 0 {
			lineStart = &r.LineNumber
		}

		description := fmt.Sprintf("[%s] %s", r.Category, r.Message)
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      r.Coordinates,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			LineStart:   lineStart,
		})
	}

	return findings, nil
}
