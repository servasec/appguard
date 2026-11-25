package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type secretlintOutput struct {
	Messages []secretlintMessage `json:"messages"`
}

type secretlintMessage struct {
	Message  string `json:"message"`
	FilePath string `json:"filePath"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	RuleID   string `json:"ruleId"`
}

func ParseSecretlint(data []byte, filename string) ([]FindingInput, error) {
	var output secretlintOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid secretlint JSON: %w", err)
	}

	var findings []FindingInput
	for _, m := range output.Messages {
		severity := "medium"

		title := m.Message
		if title == "" {
			title = m.RuleID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := m.FilePath
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if m.Line > 0 {
			lineStart = &m.Line
		}

		ruleID := m.RuleID
		if ruleID == "" {
			ruleID = "secretlint"
		}

		description := m.Message
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
