package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type wpscanOutput struct {
	Vulns map[string]wpscanVuln `json:"vulns"`
}

type wpscanVuln struct {
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	FixVersion string `json:"fix_version"`
}

func ParseWpscan(data []byte, filename string) ([]FindingInput, error) {
	var output wpscanOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid wpscan JSON: %w", err)
	}

	var findings []FindingInput
	for id, v := range output.Vulns {
		severity := strings.ToLower(v.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := v.Title
		if title == "" {
			title = id
		}
		if len(title) > 500 {
			title = title[:500]
		}

		description := v.Title
		if description == "" {
			description = id
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		remediation := ""
		if v.FixVersion != "" {
			remediation = fmt.Sprintf("Upgrade to version %s", v.FixVersion)
		}

		findings = append(findings, FindingInput{
			RuleID:      id,
			Title:       title,
			Severity:    severity,
			Description: description,
			Remediation: remediation,
		})
	}

	return findings, nil
}
