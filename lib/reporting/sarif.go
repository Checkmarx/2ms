package reporting

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/checkmarx/2ms/v3/lib/config"
	"github.com/checkmarx/2ms/v3/lib/secrets"
)

func writeSarif(report *Report, cfg *config.Config) (string, error) {
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

func getRuns(report *Report, cfg *config.Config) []Runs {
	return []Runs{
		{
			Tool:    getTool(report, cfg),
			Results: getResults(report),
		},
	}
}

func getTool(report *Report, cfg *config.Config) Tool {
	tool := Tool{
		Driver: Driver{
			Name:            cfg.Name,
			SemanticVersion: cfg.Version,
			Rules:           getRules(report),
		},
	}

	return tool
}

func getRules(report *Report) []*SarifRule {
	uniqueRulesMap := make(map[string]*SarifRule)
	var reportRules []*SarifRule
	for _, reportSecrets := range report.Results {
		for _, secret := range reportSecrets {
			if _, exists := uniqueRulesMap[secret.RuleID]; !exists {
				uniqueRulesMap[secret.RuleID] = &SarifRule{
					ID: secret.RuleID,
					FullDescription: &Message{
						Text: secret.RuleDescription,
					},
				}
				reportRules = append(reportRules, uniqueRulesMap[secret.RuleID])
			}
		}
	}
	return reportRules
}

func hasNoResults(report *Report) bool {
	return len(report.Results) == 0
}

func createMessageText(ruleName, filePath string) string {
	// maintain only the filename if the scan target is git
	if strings.HasPrefix(filePath, "git show ") {
		filePathParts := strings.SplitN(filePath, ":", 2)
		if len(filePathParts) == 2 {
			filePath = filePathParts[1]
		}
	}

	return fmt.Sprintf("%s has detected secret for file %s.", ruleName, filePath)
}

func getResults(report *Report) []Results {
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
					Text: createMessageText(secret.RuleID, secret.Source),
				},
				RuleId:    secret.RuleID,
				Locations: getLocation(secret),
				Properties: Properties{
					"validationStatus": secret.ValidationStatus,
					"cvssScore":        secret.CvssScore,
				},
			}
			results = append(results, r)
		}
	}
	return results
}

func getLocation(secret *secrets.Secret) []Locations {
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
						Properties: Properties{
							"lineContent": strings.TrimSpace(secret.LineContent),
						},
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
	Name            string       `json:"name"`
	SemanticVersion string       `json:"semanticVersion"`
	Rules           []*SarifRule `json:"rules,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type SarifRule struct {
	ID              string   `json:"id"`
	FullDescription *Message `json:"fullDescription,omitempty"`
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
	Text       string     `json:"text"`
	Properties Properties `json:"properties,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type Results struct {
	Message    Message     `json:"message"`
	RuleId     string      `json:"ruleId"`
	Locations  []Locations `json:"locations"`
	Properties Properties  `json:"properties,omitempty"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}

type Properties map[string]interface{}
