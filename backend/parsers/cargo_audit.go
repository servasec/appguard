package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type cargoAuditOutput struct {
	Vulnerabilities struct {
		List []cargoVulnerability `json:"list"`
	} `json:"vulnerabilities"`
}

type cargoVulnerability struct {
	Advisory cargoAdvisory `json:"advisory"`
	Package  cargoPackage  `json:"package"`
	Versions cargoVersions `json:"versions"`
}

type cargoAdvisory struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	URL         string   `json:"url"`
}

type cargoPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cargoVersions struct {
	Patched    []string `json:"patched"`
	Unaffected []string `json:"unaffected"`
}

func ParseCargoAudit(data []byte, filename string) ([]FindingInput, error) {
	var output cargoAuditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid cargo audit JSON: %w", err)
	}

	var findings []FindingInput
	for _, v := range output.Vulnerabilities.List {
		severity := strings.ToLower(v.Advisory.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := v.Advisory.Title
		if title == "" {
			title = v.Advisory.ID
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := v.Package.Name
		if v.Package.Version != "" {
			filePath = fmt.Sprintf("%s@%s", v.Package.Name, v.Package.Version)
		}

		description := v.Advisory.Description
		if v.Advisory.URL != "" {
			if description == "" {
				description = v.Advisory.URL
			} else {
				description = fmt.Sprintf("%s\nReference: %s", description, v.Advisory.URL)
			}
		}
		if description == "" {
			description = v.Advisory.Title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		remediation := ""
		if len(v.Versions.Patched) > 0 && v.Package.Name != "" {
			remediation = fmt.Sprintf("Upgrade %s to %s", v.Package.Name, v.Versions.Patched[0])
		}

		cweID := ""
		if len(v.Advisory.CWE) > 0 {
			raw := v.Advisory.CWE[0]
			if strings.HasPrefix(raw, "CWE-") {
				cweID = raw
			} else {
				cweID = "CWE-" + raw
			}
		}

		findings = append(findings, FindingInput{
			RuleID:      v.Advisory.ID,
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
