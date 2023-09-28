package reporting

import (
	"encoding/json"
	"fmt"

	"github.com/checkmarx/2ms/config"
)

func writeSarif(report Report, cfg *config.Config) (string, error) {
	sarif := Sarif{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs:    getRuns(report, cfg),
	}

	sarifReport, err := json.MarshalIndent(sarif, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed to create Sarif report with error: %v", err)
	}

	return string(sarifReport), nil
}

func getRuns(report Report, cfg *config.Config) []Runs {
	return []Runs{
		{
			Tool:    getTool(cfg),
			Results: getResults(report),
		},
	}
}

func getTool(cfg *config.Config) Tool {
	tool := Tool{
		Driver: Driver{
			Name:            cfg.Name,
			SemanticVersion: cfg.Version,
		},
	}

	return tool
}

func hasNoResults(report Report) bool {
	return len(report.Results) == 0
}

func messageText(ruleName string, filePath string) string {
	return fmt.Sprintf("%s has detected secret for file %s.", ruleName, filePath)
}

func getResults(report Report) []Results {
	var results []Results

	// if this report has no results, ensure that it is represented as [] instead of null/nil
	if hasNoResults(report) {
		results = make([]Results, 0)
		return results
	}

	for _, secrets := range report.Results {
		for _, secret := range secrets {
			r := Results{
				Message: Message{
					Text: messageText(secret.RuleID, secret.Source),
				},
				RuleId:    secret.RuleID,
				Locations: getLocation(secret),
			}
			results = append(results, r)
		}
	}
	return results
}

func getLocation(secret Secret) []Locations {
	return []Locations{
		{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: secret.Source,
				},
				Region: Region{
					StartLine:   secret.StartLine,
					EndLine:     secret.EndLine,
					StartColumn: secret.StartColumn,
					EndColumn:   secret.EndColumn,
					Snippet: Snippet{
						Text: secret.Value,
					},
				},
			},
		},
	}
}

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}
type ShortDescription struct {
	Text string `json:"text"`
}

type Driver struct {
	Name            string `json:"name"`
	SemanticVersion string `json:"semanticVersion"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Message struct {
	Text string `json:"text"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int     `json:"startLine"`
	StartColumn int     `json:"startColumn"`
	EndLine     int     `json:"endLine"`
	EndColumn   int     `json:"endColumn"`
	Snippet     Snippet `json:"snippet"`
}

type Snippet struct {
	Text string `json:"text"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type Results struct {
	Message   Message     `json:"message"`
	RuleId    string      `json:"ruleId"`
	Locations []Locations `json:"locations"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}
