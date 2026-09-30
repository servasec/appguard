package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

type httpxOutput struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	WebServer     string   `json:"webserver"`
	ContentLength int      `json:"content_length"`
	Vhost         string   `json:"vhost"`
}

func ParseHttpx(data []byte, filename string) ([]FindingInput, error) {
	var results []httpxOutput
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("invalid httpx JSON: %w", err)
	}

	var findings []FindingInput
	for _, r := range results {
		severity := "info"

		title := r.URL
		if r.Title != "" {
			title = r.Title
		}
		if len(title) > 500 {
			title = title[:500]
		}

		filePath := r.URL
		if filePath == "" {
			filePath = "/"
		}

		description := fmt.Sprintf("Status %d", r.StatusCode)
		if r.WebServer != "" {
			description = fmt.Sprintf("%s - %s", description, r.WebServer)
		}
		if len(r.Tech) > 0 {
			description = fmt.Sprintf("%s [%s]", description, strings.Join(r.Tech, ", "))
		}
		if len(description) > 2000 {
			description = description[:2000]
		}

		findings = append(findings, FindingInput{
			RuleID:      fmt.Sprintf("httpx-%d", r.StatusCode),
			Title:       title,
			Severity:    severity,
			Description: description,
			FilePath:    filePath,
		})
	}

	return findings, nil
}
