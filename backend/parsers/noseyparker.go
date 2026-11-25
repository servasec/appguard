package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type noseyparkerOutput struct {
	Metadata struct {
		Workspace string `json:"workspace"`
	} `json:"metadata"`
	Matches []noseyparkerMatch `json:"matches"`
}

type noseyparkerMatch struct {
	Rule           string `json:"rule"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	LineRange      []int  `json:"lineRange"`
	MatchedContent string `json:"matchedContent"`
	SourceSpan     struct {
		Start struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"start"`
	} `json:"source_span"`
}

func ParseNoseyparker(data []byte, filename string) ([]FindingInput, error) {
	var output noseyparkerOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid noseyparker JSON: %w", err)
	}

	var findings []FindingInput
	for _, m := range output.Matches {
		severity := "high"

		title := m.Rule
		if title == "" {
			title = "Secret detected"
		}
		if len(title) > 500 {
			title = title[:500]
		}

		ruleID := m.Rule
		if ruleID == "" {
			ruleID = "noseyparker"
		}

		filePath := m.Path
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if m.SourceSpan.Start.Line > 0 {
			lineStart = &m.SourceSpan.Start.Line
		} else if len(m.LineRange) > 0 && m.LineRange[0] > 0 {
			lineStart = &m.LineRange[0]
		}

		description := m.Name
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			LineStart:   lineStart,
		})
	}

	return findings, nil
}
