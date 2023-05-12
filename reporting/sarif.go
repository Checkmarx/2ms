package reporting

import (
	"encoding/json"
	"github.com/checkmarx/2ms/config"
	"io"
)

func writeSarif(report Report, w io.WriteCloser, cfg *config.Config) error {
	sarif := Sarif{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs:    getRuns(report, cfg),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(sarif)
}

func getRuns(report Report, cfg *config.Config) []Runs {
	return []Runs{
		{
			Tool:    getTool(cfg),
			Summary: getSummary(report),
			Results: getResults(report),
		},
	}
}

func getTool(cfg *config.Config) Tool {
	tool := Tool{
		Name:            cfg.Name,
		SemanticVersion: cfg.Version,
	}

	// if this tool has no rules, ensure that it is represented as [] instead of null/nil
	if hasEmptyRules(tool) {
		tool.Rules = make([]Rules, 0)
	}

	return tool
}

func hasEmptyRules(tool Tool) bool {
	return len(tool.Rules) == 0
}

func getSummary(report Report) Summary {
	return Summary{TotalItemsScanned: report.TotalItemsScanned,
		TotalItemsWithSecrets: len(report.Results),
		TotalSecretsFound:     report.TotalSecretsFound,
	}
}

func getResults(report Report) []Results {
	var results []Results
	for _, secrets := range report.Results {
		for _, secret := range secrets {
			r := Results{
				ItemSource: secret.Source,
				RuleId:     secret.Description,
				Locations:  getLocations(secret),
			}
			results = append(results, r)
		}
	}
	return results
}

func getLocations(secret Secret) []Locations {
	return []Locations{
		{
			ItemId: secret.ID,
			Region: Region{
				StartLine:   secret.StartLine,
				EndLine:     secret.EndLine,
				StartColumn: secret.StartColumn,
				EndColumn:   secret.EndColumn,
				Value: Value{
					Text: secret.Value,
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

type Rules struct {
	Name string `json:"name"`
}

type Tool struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	Rules           []Rules `json:"rules"`
}

type Region struct {
	StartLine   int   `json:"startLine"`
	StartColumn int   `json:"startColumn"`
	EndLine     int   `json:"endLine"`
	EndColumn   int   `json:"endColumn"`
	Value       Value `json:"value"`
}

type Value struct {
	Text string `json:"text"`
}

type Locations struct {
	ItemId string `json:"itemId"`
	Region Region `json:"region"`
}

type Results struct {
	ItemSource string      `json:"itemSource"`
	RuleId     string      `json:"ruleId"`
	Locations  []Locations `json:"location"`
}

type Summary struct {
	TotalItemsScanned     int `json:"totalItemsScanned"`
	TotalItemsWithSecrets int `json:"totalItemsWithSecrets"`
	TotalSecretsFound     int `json:"totalSecretsFound"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Summary Summary   `json:"summary"`
	Results []Results `json:"results"`
}
