package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type pmdOutput struct {
	Files []pmdFile `json:"files"`
}

type pmdFile struct {
	Filename   string         `json:"filename"`
	Violations []pmdViolation `json:"violations"`
}

type pmdViolation struct {
	BeginLine   int    `json:"beginline"`
	EndLine     int    `json:"endline"`
	Rule        string `json:"rule"`
	Ruleset     string `json:"ruleset"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

func ParsePmd(data []byte, filename string) ([]FindingInput, error) {
	var output pmdOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid pmd JSON: %w", err)
	}

	var findings []FindingInput
	for _, f := range output.Files {
		for _, v := range f.Violations {
			severity := "medium"
			switch v.Priority {
			case 1, 2:
				severity = "high"
			case 4, 5:
				severity = "low"
			}

			title := v.Description
			if title == "" {
				title = v.Rule
			}
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := f.Filename
			if filePath != "" && !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			var lineStart, lineEnd *int
			if v.BeginLine > 0 {
				lineStart = &v.BeginLine
				if v.EndLine >= v.BeginLine {
					lineEnd = &v.EndLine
				}
			}

			description := v.Description
			if v.Ruleset != "" {
				description = fmt.Sprintf("[%s] %s", v.Ruleset, v.Description)
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      v.Rule,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
				LineStart:   lineStart,
				LineEnd:     lineEnd,
			})
		}
	}

	return findings, nil
}
