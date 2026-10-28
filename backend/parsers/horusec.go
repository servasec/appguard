package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type horusecOutput struct {
	AnalysisVulnerabilities []horusecAnalysisVuln `json:"analysisVulnerabilities"`
}

type horusecAnalysisVuln struct {
	Vulnerabilities []horusecVulnerability `json:"vulnerabilities"`
}

type horusecVulnerability struct {
	RuleID     string `json:"ruleID"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Details    string `json:"details"`
	Severity   string `json:"severity"`
}

func ParseHorusec(data []byte, filename string) ([]FindingInput, error) {
	var output horusecOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid horusec JSON: %w", err)
	}

	var findings []FindingInput
	for _, a := range output.AnalysisVulnerabilities {
		for _, v := range a.Vulnerabilities {
			severity := strings.ToLower(v.Severity)
			if err := validateSeverity(severity); err != nil {
				severity = strings.ToLower(v.Confidence)
				if err := validateSeverity(severity); err != nil {
					severity = "medium"
				}
			}

			title := v.Details
			if title == "" {
				title = v.RuleID
			}
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := v.File
			if filePath != "" && !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			var lineStart *int
			if v.Line > 0 {
				lineStart = &v.Line
			}

			description := v.Details
			if description == "" {
				description = v.Code
			}
			if description == "" {
				description = title
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      v.RuleID,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
				LineStart:   lineStart,
			})
		}
	}

	return findings, nil
}
