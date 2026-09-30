package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type kubeauditOutput struct {
	Kubeaudit []kubeauditEvent `json:"kubeaudit"`
}

type kubeauditEvent struct {
	AuditResult struct {
		LevelName string `json:"levelname"`
		Msg       string `json:"msg"`
		Resource  struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Kind      string `json:"kind"`
		} `json:"resource"`
		Metadata struct {
			Container string `json:"container"`
		} `json:"metadata"`
	} `json:"auditResult"`
}

func ParseKubeaudit(data []byte, filename string) ([]FindingInput, error) {
	var output kubeauditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid kubeaudit JSON: %w", err)
	}

	var findings []FindingInput
	for _, e := range output.Kubeaudit {
		severity := strings.ToLower(e.AuditResult.LevelName)

		switch severity {
		case "info", "informational":
			severity = "low"
		case "warning", "warn":
			severity = "medium"
		case "error":
			severity = "high"
		}
		if err := validateSeverity(severity); err != nil {
			severity = "medium"
		}

		title := e.AuditResult.Msg
		if title == "" {
			title = severity
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := e.AuditResult.Resource.Name
		if filePath == "" {
			filePath = "/"
		} else if !filepath.IsAbs(filePath) {
			filePath = "/" + filePath
		}

		description := e.AuditResult.Msg
		if e.AuditResult.Resource.Kind != "" && e.AuditResult.Resource.Namespace != "" {
			description = fmt.Sprintf("[%s %s/%s] %s",
				e.AuditResult.Resource.Kind,
				e.AuditResult.Resource.Namespace,
				e.AuditResult.Resource.Name,
				e.AuditResult.Msg)
		}
		if e.AuditResult.Metadata.Container != "" {
			description = fmt.Sprintf("Container %s: %s", e.AuditResult.Metadata.Container, description)
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      fmt.Sprintf("kubeaudit-%s", e.AuditResult.Resource.Name),
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
