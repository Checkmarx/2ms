package reporting

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/checkmarx/2ms/v5/lib/config"
	"github.com/checkmarx/2ms/v5/lib/secrets"
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

// writeSarifToWriter streams the SARIF report directly to w, marshaling each
// result individually so that only one result's JSON is in memory at a time.
// This eliminates the intermediate Sarif struct, full []byte, and string copies
// that writeSarif produces.
func writeSarifToWriter(w io.Writer, report *Report, cfg *config.Config) error {
	bw := bufio.NewWriter(w)

	// Schema and version
	_, _ = bw.WriteString("{\n")
	_, _ = bw.WriteString(" \"$schema\": \"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json\",\n")
	_, _ = bw.WriteString(" \"version\": \"2.1.0\",\n")
	_, _ = bw.WriteString(" \"runs\": [\n")
	_, _ = bw.WriteString("  {\n")

	// Tool section (small — safe to marshal in one shot)
	tool := getTool(report, cfg)
	toolJSON, err := json.MarshalIndent(tool, "   ", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal tool: %w", err)
	}
	_, _ = bw.WriteString("   \"tool\": ")
	_, _ = bw.Write(toolJSON)
	_, _ = bw.WriteString(",\n")

	// Results — stream one at a time
	_, _ = bw.WriteString("   \"results\": [\n")

	first := true
	for _, secretsSlice := range report.Results {
		for _, secret := range secretsSlice {
			if !first {
				_, _ = bw.WriteString(",\n")
			}
			result := buildSarifResult(secret)
			resultJSON, err := json.MarshalIndent(result, "    ", " ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %w", err)
			}
			_, _ = bw.WriteString("    ")
			_, _ = bw.Write(resultJSON)
			first = false
		}
	}
	if !first {
		_, _ = bw.WriteString("\n")
	}

	_, _ = bw.WriteString("   ]\n")
	_, _ = bw.WriteString("  }\n")
	_, _ = bw.WriteString(" ]\n")
	_, _ = bw.WriteString("}\n")

	return bw.Flush()
}

// buildSarifResult converts a single Secret into a SARIF Results object.
func buildSarifResult(secret *secrets.Secret) Results {
	props := Properties{
		"validationStatus": secret.ValidationStatus,
		"cvssScore":        secret.CvssScore,
		"resultId":         secret.ID,
		"severity":         secret.Severity,
		"ruleName":         secret.RuleName,
	}

	if secret.ExtraDetails != nil {
		if pageID, ok := secret.ExtraDetails["confluence.pageId"]; ok {
			props["confluence.pageId"] = pageID
		}
	}

	return Results{
		Message: Message{
			Text: createMessageText(secret.RuleName, secret.Source),
		},
		RuleId:     secret.RuleID,
		Locations:  getLocation(secret),
		Properties: props,
	}
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
					ID:   secret.RuleID,
					Name: secret.RuleName,
					FullDescription: &Message{
						Text: secret.RuleDescription,
					},
					Properties: Properties{
						"category": secret.RuleCategory,
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

	for _, secretsSlice := range report.Results {
		for _, secret := range secretsSlice {
			results = append(results, buildSarifResult(secret))
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
	ID              string     `json:"id"`
	Name            string     `json:"name,omitempty"`
	FullDescription *Message   `json:"fullDescription,omitempty"`
	Properties      Properties `json:"properties,omitempty"`
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
