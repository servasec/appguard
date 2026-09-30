package parsers

import (
	"encoding/json"
	"fmt"
)

type niktoOutput struct {
	Host            string      `json:"host"`
	IP              string      `json:"ip"`
	Port            string      `json:"port"`
	Vulnerabilities []niktoVuln `json:"vulnerabilities"`
}

type niktoVuln struct {
	ID     string `json:"id"`
	OSVDB  string `json:"OSVDB"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Msg    string `json:"msg"`
}

func ParseNikto(data []byte, filename string) ([]FindingInput, error) {
	var output niktoOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid nikto JSON: %w", err)
	}

	var findings []FindingInput
	for _, v := range output.Vulnerabilities {
		severity := "medium"

		title := v.Msg
		if title == "" {
			title = fmt.Sprintf("Nikto finding %s", v.ID)
		}
		if len(title) > 500 {
			title = title[:500]
		}

		ruleID := v.ID
		if v.OSVDB != "" && v.OSVDB != "0" {
			ruleID = "OSVDB-" + v.OSVDB
		}

		filePath := v.URL
		if filePath == "" {
			filePath = "/"
		}

		description := v.Msg
		if v.Method != "" && v.URL != "" {
			description = fmt.Sprintf("[%s %s] %s", v.Method, v.URL, v.Msg)
		}
		if description == "" {
			description = title
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}

// ParseNiktoJSONL handles JSONL format output.
func ParseNiktoJSONL(data []byte, filename string) ([]FindingInput, error) {
	var output []niktoOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid nikto JSON: %w", err)
	}

	var findings []FindingInput
	for _, host := range output {
		for _, v := range host.Vulnerabilities {
			severity := "medium"

			title := v.Msg
			if title == "" {
				title = fmt.Sprintf("Nikto finding %s", v.ID)
			}
			if len(title) > 500 {
				title = title[:500]
			}

			ruleID := v.ID
			if v.OSVDB != "" && v.OSVDB != "0" {
				ruleID = "OSVDB-" + v.OSVDB
			}

			filePath := v.URL
			if filePath == "" {
				filePath = "/"
			}

			description := v.Msg
			if v.Method != "" && v.URL != "" {
				description = fmt.Sprintf("[%s %s] %s", v.Method, v.URL, v.Msg)
			}
			if description == "" {
				description = title
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      ruleID,
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
			})
		}
	}

	return findings, nil
}
