package parsers

import (
	"encoding/json"
	"fmt"
)

type pipAuditOutput struct {
	Dependencies []pipAuditDependency `json:"dependencies"`
}

type pipAuditDependency struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Vulns   []pipAuditVuln `json:"vulns"`
}

type pipAuditVuln struct {
	ID             string   `json:"id"`
	Description    string   `json:"description"`
	FixVersions    []string `json:"fix_versions"`
	AffectedRanges []string `json:"affected_ranges"`
}

func ParsePipAudit(data []byte, filename string) ([]FindingInput, error) {
	var output pipAuditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid pip-audit JSON: %w", err)
	}

	var findings []FindingInput
	for _, dep := range output.Dependencies {
		for _, vuln := range dep.Vulns {
			severity := "medium"

			title := vuln.Description
			if title == "" {
				title = fmt.Sprintf("Vulnerability in %s %s: %s", dep.Name, dep.Version, vuln.ID)
			}
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := dep.Name
			if dep.Version != "" {
				filePath = fmt.Sprintf("%s@%s", dep.Name, dep.Version)
			}

			description := fmt.Sprintf("%s %s is affected: %s", dep.Name, dep.Version, vuln.ID)
			if vuln.Description != "" {
				description = vuln.Description
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			remediation := ""
			if len(vuln.FixVersions) > 0 {
				remediation = fmt.Sprintf("Upgrade %s to %s", dep.Name, vuln.FixVersions[len(vuln.FixVersions)-1])
			}

			findings = append(findings, FindingInput{
				RuleID:      vuln.ID,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
				Remediation: remediation,
			})
		}
	}

	return findings, nil
}
