package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// trivy-operator reports results in trivy-compatible JSON: the ResourceReport
// spec exposes [Results], each holding a target (workload) and its
// vulnerabilities/misconfigurations. Parsing reuses the trivy conventions.
type trivyOperatorOutput struct {
	Spec struct {
		Results []trivyResult `json:"results"`
	} `json:"spec"`
}

func ParseTrivyOperator(data []byte, filename string) ([]FindingInput, error) {
	var output trivyOperatorOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid trivy-operator JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range output.Spec.Results {
		for _, v := range r.Vulnerabilities {
			severity := strings.ToLower(v.Severity)
			if err := validateSeverity(severity); err != nil {
				severity = "medium"
			}

			title := v.VulnerabilityID
			if v.Title != "" {
				title = v.Title
				if len(title) > 500 {
					title = title[:500]
				}
			}

			description := v.Description
			if v.PkgName != "" && v.InstalledVersion != "" && v.FixedVersion != "" {
				description = fmt.Sprintf("%s@%s - fixed in %s: %s", v.PkgName, v.InstalledVersion, v.FixedVersion, v.Description)
			} else if v.Description != "" {
				description = v.Description
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			remediation := ""
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Upgrade %s to version %s", v.PkgName, v.FixedVersion)
			}

			findings = append(findings, FindingInput{
				RuleID:      v.VulnerabilityID,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    r.Target,
				Remediation: remediation,
			})
		}

		for _, m := range r.Misconfigurations {
			severity := strings.ToLower(m.Severity)
			if err := validateSeverity(severity); err != nil {
				severity = "medium"
			}

			title := m.ID
			if m.Title != "" {
				title = m.Title
				if len(title) > 500 {
					title = title[:500]
				}
			}

			findings = append(findings, FindingInput{
				RuleID:      m.ID,
				Title:       title,
				Severity:    severity,
				Description: m.Message,
				FilePath:    r.Target,
			})
		}
	}

	return findings, nil
}
