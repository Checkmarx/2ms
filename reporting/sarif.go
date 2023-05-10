package reporting

import (
	"encoding/json"
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config"
	"io"
)

func writeSarif(report Report, w io.WriteCloser, orderedRules []config.Rule) error {
	sarif := Sarif{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs:    getRuns(orderedRules, report),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(sarif)
}

func getRuns(orderedRules []config.Rule, report Report) []Runs {
	return []Runs{
		{
			Tool:    getTool(orderedRules),
			Results: getResults(report),
		},
	}
}

func getTool(orderedRules []config.Rule) Tool {
	tool := Tool{
		Driver: Driver{
			Name:            "2ms",
			SemanticVersion: "v1.2.3", //cmd.Version,
			Rules:           getRules(orderedRules),
		},
	}

	// if this tool has no rules, ensure that it is represented as [] instead of null/nil
	if hasEmptyRules(tool) {
		tool.Driver.Rules = make([]Rules, 0)
	}

	return tool
}

func hasEmptyRules(tool Tool) bool {
	return len(tool.Driver.Rules) == 0
}

func getRules(orderedRules []config.Rule) []Rules {
	var rules []Rules
	for _, rule := range orderedRules {
		shortDescription := ShortDescription{
			Text: rule.Description,
		}
		if rule.Regex != nil {
			shortDescription = ShortDescription{
				Text: rule.Regex.String(),
			}
		} else if rule.Path != nil {
			shortDescription = ShortDescription{
				Text: rule.Path.String(),
			}
		}
		rules = append(rules, Rules{
			ID:          rule.RuleID,
			Name:        rule.Description,
			Description: shortDescription,
		})
	}
	return rules
}

func messageText(secret Secret) string {
	return fmt.Sprintf("%s has detected secret for file %s.", secret.Description, secret.ID)
}

func getResults(report Report) []Results {
	var results []Results
	for _, secrets := range report.Results {
		for _, secret := range secrets {
			r := Results{
				Message: Message{
					Text: messageText(secret),
				},
				RuleId:    secret.Description,
				Locations: getLocation(secret),
			}
			results = append(results, r)
		}
	}
	return results
}

func getLocation(secret Secret) []Locations {
	uri := secret.ID
	return []Locations{
		{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: uri,
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

type FullDescription struct {
	Text string `json:"text"`
}

type Rules struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description ShortDescription `json:"shortDescription"`
}

type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	Rules           []Rules `json:"rules"`
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
