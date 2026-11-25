package parsers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type nmapOutput struct {
	NmapRun struct {
		Hosts []nmapHost `json:"host"`
	} `json:"nmaprun"`
}

type nmapHost struct {
	Ports struct {
		Port []nmapPort `json:"port"`
	} `json:"ports"`
}

type nmapPort struct {
	Protocol string `json:"protocol"`
	PortID   string `json:"portid"`
	State    struct {
		State string `json:"state"`
	} `json:"state"`
	Service struct {
		Name    string `json:"name"`
		Product string `json:"product"`
		Version string `json:"version"`
	} `json:"service"`
}

func ParseNmap(data []byte, filename string) ([]FindingInput, error) {
	var output nmapOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid nmap JSON: %w", err)
	}

	var findings []FindingInput
	for _, host := range output.NmapRun.Hosts {
		for _, p := range host.Ports.Port {
			if p.State.State != "open" {
				continue
			}

			severity := "info"

			service := p.Service.Name
			if service == "" {
				service = "unknown"
			}

			portNum := fmt.Sprintf("%s/%s", p.PortID, p.Protocol)

			title := fmt.Sprintf("Open port: %s (%s)", portNum, service)
			if p.Service.Product != "" {
				title = fmt.Sprintf("Open port: %s (%s %s)", portNum, p.Service.Product, p.Service.Version)
			}
			if len(title) > 500 {
				title = title[:500]
			}

			filePath := portNum
			if !filepath.IsAbs(filePath) {
				filePath = "/" + filePath
			}

			description := fmt.Sprintf("Port %s open (%s)", portNum, service)
			if p.Service.Product != "" {
				description = fmt.Sprintf("Port %s: %s %s", portNum, p.Service.Product, p.Service.Version)
			}
			if len(description) > 2000 {
				description = description[:2000]
			}

			findings = append(findings, FindingInput{
				RuleID:      fmt.Sprintf("port-%s", portNum),
				Title:       title,
				Severity:    severity,
				Description: description,
				FilePath:    filePath,
			})
		}
	}

	return findings, nil
}
