package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type govulncheckOutput struct {
	Vulns []govulncheckVuln `json:"vulns"`
}

type govulncheckVuln struct {
	OSV     govulncheckOSV      `json:"osv"`
	Aliases []string            `json:"aliases"`
	Modules []govulncheckModule `json:"modules"`
}

type govulncheckOSV struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type govulncheckModule struct {
	Path      string               `json:"path"`
	Versions  string               `json:"versions"`
	Available govulncheckAvailable `json:"available"`
}

type govulncheckAvailable struct {
	Version string `json:"version"`
	Next    string `json:"next"`
}

func ParseGovulncheck(data []byte, filename string) ([]FindingInput, error) {
	var output govulncheckOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid govulncheck JSON: %w", err)
	}

	var findings []FindingInput
	for _, vuln := range output.Vulns {
		severity := "medium"
		title := vuln.OSV.Summary
		if title == "" {
			title = vuln.OSV.ID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		modulePath := ""
		remediation := ""
		if len(vuln.Modules) > 0 {
			mod := vuln.Modules[0]
			modulePath = mod.Path
			if mod.Available.Next != "" {
				remediation = fmt.Sprintf("Upgrade %s to %s", mod.Path, mod.Available.Next)
			} else if mod.Available.Version != "" {
				remediation = fmt.Sprintf("Upgrade %s to %s", mod.Path, mod.Available.Version)
			}
		}

		filePath := modulePath
		if filePath == "" {
			filePath = "/"
		} else if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := vuln.OSV.Summary
		if len(vuln.Aliases) > 0 {
			description = fmt.Sprintf("%s (aliases: %s)", description, strings.Join(vuln.Aliases, ", "))
		}
		if description == "" {
			description = vuln.OSV.ID
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		cweID := ""
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "CWE-") {
				cweID = alias
				break
			}
		}

		findings = append(findings, FindingInput{
			RuleID:      vuln.OSV.ID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			Remediation: remediation,
			CWEID:       cweID,
		})
	}

	return findings, nil
}
