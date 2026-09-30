package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// yarn audit --json emits one JSON object per line (JSONL). Only lines of type
// "auditAdvisory" carry vulnerability data.
type yarnAuditLine struct {
	Type string        `json:"type"`
	Data yarnAuditData `json:"data"`
}

type yarnAuditData struct {
	Advisory yarnAuditAdvisory `json:"advisory"`
}

type yarnAuditAdvisory struct {
	ID                 int      `json:"id"`
	Title              string   `json:"title"`
	ModuleName         string   `json:"module_name"`
	Severity           string   `json:"severity"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	PatchedVersions    string   `json:"patched_versions"`
	Recommendation     string   `json:"recommendation"`
	Cves               []string `json:"cves"`
}

func ParseYarnAudit(data []byte, filename string) ([]FindingInput, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty yarn audit input")
	}

	var findings []FindingInput
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		var l yarnAuditLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			return nil, fmt.Errorf("invalid yarn audit JSON on line %d: %w", lineNum, err)
		}
		if l.Type != "auditAdvisory" {
			continue
		}

		advisory := l.Data.Advisory

		severity := strings.ToLower(advisory.Severity)
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := advisory.Title
		if title == "" {
			title = fmt.Sprintf("Vulnerability in %s", advisory.ModuleName)
		}
		if len(title) > 500 {
			title = title[:500]
		}

		ruleID := fmt.Sprintf("YARN-%d", advisory.ID)
		if len(advisory.Cves) > 0 && advisory.Cves[0] != "" {
			ruleID = advisory.Cves[0]
		}

		filePath := advisory.ModuleName
		if advisory.VulnerableVersions != "" {
			filePath = fmt.Sprintf("%s@%s", advisory.ModuleName, advisory.VulnerableVersions)
		}

		description := advisory.Title
		if advisory.Recommendation != "" {
			description = fmt.Sprintf("%s\nRecommendation: %s", description, advisory.Recommendation)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		remediation := ""
		if advisory.PatchedVersions != "" && advisory.ModuleName != "" {
			remediation = fmt.Sprintf("Upgrade %s to %s", advisory.ModuleName, advisory.PatchedVersions)
		}

		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
			Remediation: remediation,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading yarn audit input: %w", err)
	}

	return findings, nil
}
