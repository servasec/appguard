package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type naabuOutput struct {
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proto string `json:"protocol"`
}

func ParseNaabu(data []byte, filename string) ([]FindingInput, error) {
	var results []naabuOutput
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("invalid naabu JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range results {
		severity := "info"

		portNum := fmt.Sprintf("%d/%s", r.Port, r.Proto)
		if r.Proto == "" {
			portNum = fmt.Sprintf("%d/tcp", r.Port)
		}

		title := fmt.Sprintf("Open port: %s", portNum)
		filePath := portNum
		if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := fmt.Sprintf("Port %s open on %s", portNum, r.Host)
		if r.IP != "" && r.IP != r.Host {
			description = fmt.Sprintf("Port %s open on %s (%s)", portNum, r.Host, r.IP)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      fmt.Sprintf("naabu-port-%d", r.Port),
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
