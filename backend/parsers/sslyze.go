package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type sslyzeOutput struct {
	Target          sslyzeTarget `json:"target"`
	CommandsResults struct {
		Heartbleed      *sslyzeResult `json:"heartbleed"`
		Compression     *sslyzeResult `json:"compression"`
		Renegotiation   *sslyzeResult `json:"renegotiation"`
		CertificateInfo *sslyzeResult `json:"certificate_information"`
		SSLv2           *sslyzeResult `json:"ssl_2_0_cipher_suites"`
		SSLv3           *sslyzeResult `json:"ssl_3_0_cipher_suites"`
		TLSv10          *sslyzeResult `json:"tls_1_0_cipher_suites"`
		TLSv11          *sslyzeResult `json:"tls_1_1_cipher_suites"`
		TLSv12          *sslyzeResult `json:"tls_1_2_cipher_suites"`
		TLSv13          *sslyzeResult `json:"tls_1_3_cipher_suites"`
	} `json:"commands_results"`
}

type sslyzeTarget struct {
	Hostname string `json:"hostname"`
}

type sslyzeResult struct {
	Result string `json:"result"`
}

func ParseSslyze(data []byte, filename string) ([]FindingInput, error) {
	var output sslyzeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid sslyze JSON: %w", err)
	}

	hostname := output.Target.Hostname
	if hostname == "" {
		hostname = "/"
	}

	var findings []FindingInput
	addFinding := func(ruleID, title, result string, severity string) {
		if result == "" {
			return
		}
		titleVal := title
		if len(titleVal) > 500 {
			titleVal = titleVal[:500]
		}
		description := result
		if len(description) > 2000 {
			description = description[:2000]
		}
		findings = append(findings, FindingInput{
			RuleID:      ruleID,
			Title:       titleVal,
			Severity:    severity,
			Description: description,
			FilePath:    hostname,
		})
	}

	// Only report results that indicate actual issues (not "NOT_VULNERABLE").
	checkResult := func(name string, res *sslyzeResult, vulnID string, vulnTitle string) {
		if res == nil {
			return
		}
		r := strings.ToUpper(res.Result)
		if strings.Contains(r, "NOT_VULNERABLE") || r == "" || r == "OK" {
			return
		}
		severity := "high"
		if strings.Contains(r, "VULNERABLE") {
			severity = "critical"
		}
		addFinding(vulnID, vulnTitle, res.Result, severity)
	}

	checkResult("Heartbleed", output.CommandsResults.Heartbleed, "SSLYZE-HEARTBLEED", "SSL/TLS Heartbleed")
	checkResult("Compression", output.CommandsResults.Compression, "SSLYZE-COMPRESSION", "SSL/TLS CRIME compression")
	checkResult("Renegotiation", output.CommandsResults.Renegotiation, "SSLYZE-RENEGOTIATION", "SSL/TLS insecure renegotiation")

	return findings, nil
}
