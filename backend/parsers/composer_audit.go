package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type composerAuditOutput struct {
	Advisories map[string][]composerAdvisory `json:"advisories"`
}

type composerAdvisory struct {
	AdvisoryID       string `json:"advisoryId"`
	PackageName      string `json:"packageName"`
	Title            string `json:"title"`
	CVE              string `json:"cve"`
	Link             string `json:"link"`
	AffectedVersions string `json:"affectedVersions"`
}

func ParseComposerAudit(data []byte, filename string) ([]FindingInput, error) {
	var output composerAuditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid composer audit JSON: %w", err)
	}

	var findings []FindingInput
	for _, advisories := range output.Advisories {
		for _, advisory := range advisories {
			severity := "medium"

			title := advisory.Title
			if title == "" {
				title = advisory.AdvisoryID
			}
			if len(title) > 500 {
				title = title[:500]
			}

			ruleID := advisory.AdvisoryID
			if ruleID == "" {
				ruleID = advisory.CVE
			}

			pkg := advisory.PackageName

			description := advisory.Title
			if advisory.Link != "" {
				description = fmt.Sprintf("%s\nReference: %s", description, advisory.Link)
			}
			if description == "" {
				description = ruleID
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			remediation := ""
			if advisory.AffectedVersions != "" {
				remediation = fmt.Sprintf("Upgrade %s to a version outside the affected range %s", pkg, advisory.AffectedVersions)
			}

			cweID := ""
			if strings.HasPrefix(ruleID, "CWE-") {
				cweID = ruleID
			}

			findings = append(findings, FindingInput{
				RuleID:      ruleID,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    pkg,
				Remediation: remediation,
				CWEID:       cweID,
			})
		}
	}

	return findings, nil
}
