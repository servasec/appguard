package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type dockerBenchOutput []dockerBenchGroup

type dockerBenchGroup struct {
	ID      string            `json:"id"`
	Desc    string            `json:"desc"`
	Results []dockerBenchTest `json:"results"`
}

type dockerBenchTest struct {
	TestNumber string `json:"test_number"`
	TestDesc   string `json:"test_desc"`
	Fail       bool   `json:"fail"`
	Details    string `json:"details"`
}

func ParseDockerBenchSecurity(data []byte, filename string) ([]FindingInput, error) {
	var output dockerBenchOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid docker-bench-security JSON: %w", err)
	}

	var findings []FindingInput
	for _, group := range output {
		for _, test := range group.Results {
			if !test.Fail {
				continue
			}

			severity := "medium"
			switch {
			case strings.HasPrefix(test.TestNumber, "1.") || strings.HasPrefix(test.TestNumber, "2."):
				severity = "high"
			case strings.HasPrefix(test.TestNumber, "3.") || strings.HasPrefix(test.TestNumber, "4."):
				severity = "medium"
			default:
				severity = "low"
			}

			title := test.TestDesc
			if title == "" {
				title = test.TestNumber
			}
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := test.TestNumber
			if !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			description := test.Details
			if description == "" {
				description = test.TestDesc
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      test.TestNumber,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
			})
		}
	}

	return findings, nil
}
