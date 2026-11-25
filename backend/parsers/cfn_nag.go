package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type cfnNagOutput struct {
	Messages []cfnNagMessage `json:"messages"`
}

type cfnNagMessage struct {
	Type              string `json:"type"`
	Level             string `json:"level"`
	ID                string `json:"id"`
	Message           string `json:"message"`
	LogicalResourceID string `json:"logicalResourceId"`
	Filepath          string `json:"filepath"`
	LineNumber        int    `json:"lineNumber"`
}

func ParseCfnNag(data []byte, filename string) ([]FindingInput, error) {
	var output cfnNagOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid cfn-nag JSON: %w", err)
	}

	var findings []FindingInput
	for _, m := range output.Messages {
		severity := strings.ToLower(m.Level)
		if err := validateSeverity(severity); err != nil {
			if strings.HasPrefix(m.ID, "F") {
				severity = "high"
			} else {
				severity = "medium"
			}
		}

		title := m.Message
		if title == "" {
			title = m.ID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := m.Filepath
		if filePath != "" && !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		var lineStart *int
		if m.LineNumber > 0 {
			lineStart = &m.LineNumber
		}

		description := m.Message
		if m.LogicalResourceID != "" {
			description = fmt.Sprintf("[%s] %s", m.LogicalResourceID, m.Message)
		}
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      m.ID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			LineStart:   lineStart,
		})
	}

	return findings, nil
}
