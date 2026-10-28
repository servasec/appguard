package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type scoutSuiteOutput struct {
	Services map[string]scoutSuiteService `json:"services"`
}

type scoutSuiteService struct {
	Findings map[string]scoutSuiteFinding `json:"findings"`
}

type scoutSuiteFinding struct {
	Items       []json.RawMessage `json:"items"`
	Risk        string            `json:"risk"`
	Description string            `json:"description"`
	Rationale   string            `json:"rationale"`
}

func ParseScoutsuite(data []byte, filename string) ([]FindingInput, error) {
	var output scoutSuiteOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid scoutsuite JSON: %w", err)
	}

	var findings []FindingInput
	for _, service := range output.Services {
		for id, f := range service.Findings {
			severity := strings.ToLower(f.Risk)
			severity = mapRiskToSeverity(severity)
			if err := validateSeverity(severity); err != nil {
				severity = "medium"
			}

			title := f.Description
			if title == "" {
				title = id
			}
			if len(title) > 500 {
				title = title[:500]
			}

			description := f.Description
			if f.Rationale != "" {
				description = fmt.Sprintf("%s\nRationale: %s", f.Description, f.Rationale)
			}
			if description == "" {
				description = id
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      id,
				Title:       title,
				Severity:    severity,
				Description: description,
			})
		}
	}

	return findings, nil
}

func mapRiskToSeverity(risk string) string {
	switch risk {
	case "high", "critical":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "":
		return "low"
	default:
		return "medium"
	}
}
