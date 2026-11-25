package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type pnpmAuditOutput struct {
	Report pnpmAuditReport `json:"report"`
}

type pnpmAuditReport struct {
	AuditReport struct {
		Vulnerabilities map[string][]pnpmAdvisory `json:"vulnerabilities"`
	} `json:"auditReport"`
}

type pnpmAdvisory struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func ParsePnpmAudit(data []byte, filename string) ([]FindingInput, error) {
	var output pnpmAuditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid pnpm audit JSON: %w", err)
	}

	var findings []FindingInput
	for pkg, advisories := range output.Report.AuditReport.Vulnerabilities {
		for _, advisory := range advisories {
			severity := strings.ToLower(advisory.Severity)
			if err := validateSeverity(severity); err != nil {
				severity = "medium"
			}

			title := advisory.Title
			if title == "" {
				title = fmt.Sprintf("Vulnerability in %s", pkg)
			}
			if len(title) > 500 {
				title = title[:500]
			}

			description := advisory.Description
			if description == "" {
				description = advisory.Title
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      pkg,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    pkg,
			})
		}
	}

	return findings, nil
}
