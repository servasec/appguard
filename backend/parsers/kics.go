package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type kicsOutput struct {
	Queries []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName   string     `json:"query_name"`
	QueryID     string     `json:"query_id"`
	Severity    string     `json:"severity"`
	Platform    string     `json:"platform"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	Files       []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName string `json:"file_name"`
	Line     int    `json:"line"`
}

func ParseKics(data []byte, filename string) ([]FindingInput, error) {
	var output kicsOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid kics JSON: %w", err)
	}

	var findings []FindingInput
	for _, q := range output.Queries {
		severity := strings.ToLower(q.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := q.QueryName
		if title == "" {
			title = q.QueryID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		description := q.Description
		if q.Category != "" {
			description = fmt.Sprintf("[%s] %s", q.Category, q.Description)
		}
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		for _, f := range q.Files {
			filePath := f.FileName
			if filePath != "" && !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			var lineStart *int
			if f.Line > 0 {
				lineStart = &f.Line
			}

			findings = append(findings, FindingInput{
				RuleID:      q.QueryID,
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
