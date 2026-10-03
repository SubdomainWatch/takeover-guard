package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/subdomainwatch/takeover-guard/pkg/correlator"
)

type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     SarifText       `json:"shortDescription"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration SarifRuleConfig `json:"defaultConfiguration"`
	Properties           map[string]any  `json:"properties"`
}

type SarifRuleConfig struct {
	Level string `json:"level"`
}

type SarifText struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SarifText         `json:"message"`
	Locations           []SarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func GenerateSarif(findings []correlator.Finding) *SarifReport {
	rules := []SarifRule{
		{
			ID:   correlator.RuleUncoordinatedOrphan,
			Name: "UncoordinatedResourceOrphan",
			ShortDescription: SarifText{
				Text: "Cloud resource deleted while DNS record remains active",
			},
			HelpURI:              "https://subdomainwatch.com/guides/dns-takeover",
			DefaultConfiguration: SarifRuleConfig{Level: "error"},
			Properties: map[string]any{
				"tags": []string{"security", "dns", "takeover"},
			},
		},
		{
			ID:   correlator.RuleDanglingPointer,
			Name: "DanglingCnamePointer",
			ShortDescription: SarifText{
				Text: "DNS record points to an unclaimed third-party cloud service",
			},
			HelpURI:              "https://subdomainwatch.com/guides/dns-takeover",
			DefaultConfiguration: SarifRuleConfig{Level: "error"},
			Properties: map[string]any{
				"tags": []string{"security", "dns", "takeover"},
			},
		},
		{
			ID:   correlator.RuleComputedTarget,
			Name: "ComputedTargetUnknownAtPlan",
			ShortDescription: SarifText{
				Text: "Dynamic computed DNS target flagged for Post-Apply Sentinel",
			},
			HelpURI:              "https://subdomainwatch.com/guides/dns-takeover",
			DefaultConfiguration: SarifRuleConfig{Level: "warning"},
			Properties: map[string]any{
				"tags": []string{"security", "dns", "sentinel"},
			},
		},
	}

	var results []SarifResult
	for _, f := range findings {
		level := "error"
		if f.Severity == correlator.SeverityWarning {
			level = "warning"
		}

		res := SarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: SarifText{
				Text: fmt.Sprintf("%s: %s", f.Severity, f.Reason),
			},
		}

		uri := f.SourceFile
		if uri == "" {
			uri = "terraform/plan.json"
		}
		line := f.StartLine
		if line <= 0 {
			line = 1
		}

		res.Locations = []SarifLocation{
			{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{
						URI: uri,
					},
					Region: SarifRegion{
						StartLine:   line,
						StartColumn: 1,
					},
				},
			},
		}
		lineHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", f.RuleID, f.FQDN, f.Target)))
		res.PartialFingerprints = map[string]string{
			"primaryLocationLineHash": hex.EncodeToString(lineHash[:]),
		}

		results = append(results, res)
	}

	return &SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "SubdomainWatch Takeover Guard",
						Version:        "2.1.0",
						InformationURI: "https://subdomainwatch.com/spec",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

func WriteSarifFile(path string, findings []correlator.Finding) error {
	report := GenerateSarif(findings)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
