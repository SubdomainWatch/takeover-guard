package reporter

import (
	"encoding/json"
	"os"
	"time"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

type SummaryReport struct {
	Timestamp            string               `json:"timestamp"`
	ToolVersion          string               `json:"tool_version"`
	Mode                 string               `json:"mode"`
	TotalModifiedRecords int                  `json:"total_modified_records"`
	CriticalCount        int                  `json:"critical_count"`
	HighCount            int                  `json:"high_count"`
	WarningCount         int                  `json:"warning_count"`
	Findings             []correlator.Finding `json:"findings"`
}

func GenerateSummaryReport(mode string, totalModified int, findings []correlator.Finding) *SummaryReport {
	crit := 0
	high := 0
	warn := 0

	for _, f := range findings {
		switch f.Severity {
		case correlator.SeverityCritical:
			crit++
		case correlator.SeverityHigh:
			high++
		case correlator.SeverityWarning:
			warn++
		}
	}

	return &SummaryReport{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		ToolVersion:          "2.1.0",
		Mode:                 mode,
		TotalModifiedRecords: totalModified,
		CriticalCount:        crit,
		HighCount:            high,
		WarningCount:         warn,
		Findings:             findings,
	}
}

func WriteJSONFile(path string, report *SummaryReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
