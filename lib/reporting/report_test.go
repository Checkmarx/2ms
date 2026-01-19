package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/v5/lib/config"
	"github.com/checkmarx/2ms/v5/lib/secrets"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// test input results
var (
	ruleID1       = "ruleID1"
	ruleID2       = "ruleID2"
	ruleID4       = "ruleID4"
	RuleName1     = "ruleName1"
	RuleName2     = "ruleName2"
	RuleName4     = "ruleName4"
	ruleCategory1 = "category1"
	ruleCategory2 = "category2"
	ruleCategory4 = "category4"

	result1 = &secrets.Secret{
		ID:               "ID1",
		Source:           "file1",
		RuleID:           ruleID1,
		RuleName:         RuleName1,
		RuleCategory:     ruleCategory1,
		StartLine:        150,
		EndLine:          150,
		LineContent:      "line content",
		StartColumn:      31,
		EndColumn:        150,
		Value:            "value",
		ValidationStatus: secrets.ValidResult,
		CvssScore:        10.0,
		Severity:         "High",
		RuleDescription:  "Rule Description",
	}
	// this result has a different rule than result1
	result2 = &secrets.Secret{
		ID:               "ID2",
		Source:           "file2",
		RuleID:           ruleID2,
		RuleName:         RuleName2,
		RuleCategory:     ruleCategory2,
		StartLine:        10,
		EndLine:          10,
		LineContent:      "line content2",
		StartColumn:      41,
		EndColumn:        160,
		Value:            "value 2",
		ValidationStatus: secrets.InvalidResult,
		Severity:         "Medium",
		CvssScore:        4.5,
		RuleDescription:  "Rule Description2",
	}
	// this result has the same rule as result1
	result3 = &secrets.Secret{
		ID:               "ID3",
		Source:           "file3",
		RuleID:           ruleID1,
		RuleName:         RuleName1,
		RuleCategory:     ruleCategory1,
		StartLine:        16,
		EndLine:          16,
		LineContent:      "line content3",
		StartColumn:      11,
		EndColumn:        130,
		Value:            "value 3",
		ValidationStatus: secrets.UnknownResult,
		Severity:         "Low",
		CvssScore:        0.0,
		RuleDescription:  "Rule Description",
	}
	// result for confluence.pageId validation
	result4 = &secrets.Secret{
		ID:               "ID4",
		Source:           "file4",
		RuleID:           "ruleID4",
		RuleName:         RuleName4,
		RuleCategory:     ruleCategory4,
		StartLine:        0,
		EndLine:          0,
		LineContent:      "line content4",
		StartColumn:      11,
		EndColumn:        130,
		Value:            "value 4",
		ValidationStatus: secrets.UnknownResult,
		Severity:         "High",
		CvssScore:        0.0,
		RuleDescription:  "Rule Description",
		ExtraDetails: map[string]interface{}{
			"confluence.pageId": "1234567890",
		},
	}
)

// test expected outputs
var (
	// sarif rules
	rule1Sarif = &SarifRule{
		ID:   ruleID1,
		Name: RuleName1,
		FullDescription: &Message{
			Text: result1.RuleDescription,
		},
		Properties: Properties{
			"category": ruleCategory1,
		},
	}
	rule2Sarif = &SarifRule{
		ID:   ruleID2,
		Name: RuleName2,
		FullDescription: &Message{
			Text: result2.RuleDescription,
		},
		Properties: Properties{
			"category": ruleCategory2,
		},
	}
	rule4Sarif = &SarifRule{
		ID:   ruleID4,
		Name: RuleName4,
		FullDescription: &Message{
			Text: result4.RuleDescription,
		},
		Properties: Properties{
			"category": ruleCategory4,
		},
	}
	// sarif results
	result1Sarif = Results{
		Message: Message{
			Text: createMessageText(result1.RuleName, result1.Source),
		},
		RuleId: ruleID1,
		Locations: []Locations{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: result1.Source,
					},
					Region: Region{
						StartLine:   result1.StartLine,
						StartColumn: result1.StartColumn,
						EndLine:     result1.EndLine,
						EndColumn:   result1.EndColumn,
						Snippet: Snippet{
							Text: result1.Value,
							Properties: Properties{
								"lineContent": strings.TrimSpace(result1.LineContent),
							},
						},
					},
				},
			},
		},
		Properties: Properties{
			"validationStatus": string(result1.ValidationStatus),
			"cvssScore":        result1.CvssScore,
			"resultId":         result1.ID,
			"severity":         result1.Severity,
			"ruleName":         RuleName1,
		},
	}
	result2Sarif = Results{
		Message: Message{
			Text: createMessageText(result2.RuleName, result2.Source),
		},
		RuleId: ruleID2,
		Locations: []Locations{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: result2.Source,
					},
					Region: Region{
						StartLine:   result2.StartLine,
						StartColumn: result2.StartColumn,
						EndLine:     result2.EndLine,
						EndColumn:   result2.EndColumn,
						Snippet: Snippet{
							Text: result2.Value,
							Properties: Properties{
								"lineContent": strings.TrimSpace(result2.LineContent),
							},
						},
					},
				},
			},
		},
		Properties: Properties{
			"validationStatus": string(result2.ValidationStatus),
			"cvssScore":        result2.CvssScore,
			"resultId":         result2.ID,
			"severity":         result2.Severity,
			"ruleName":         RuleName2,
		},
	}
	result3Sarif = Results{
		Message: Message{
			Text: createMessageText(result3.RuleName, result3.Source),
		},
		RuleId: ruleID1,
		Locations: []Locations{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: result3.Source,
					},
					Region: Region{
						StartLine:   result3.StartLine,
						StartColumn: result3.StartColumn,
						EndLine:     result3.EndLine,
						EndColumn:   result3.EndColumn,
						Snippet: Snippet{
							Text: result3.Value,
							Properties: Properties{
								"lineContent": strings.TrimSpace(result3.LineContent),
							},
						},
					},
				},
			},
		},
		Properties: Properties{
			"validationStatus": string(result3.ValidationStatus),
			"cvssScore":        result3.CvssScore,
			"resultId":         result3.ID,
			"severity":         result3.Severity,
			"ruleName":         RuleName1,
		},
	}
	result4Sarif = Results{
		Message: Message{
			Text: createMessageText(result4.RuleName, result4.Source),
		},
		RuleId: ruleID4,
		Locations: []Locations{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: result4.Source,
					},
					Region: Region{
						StartLine:   result4.StartLine,
						StartColumn: result4.StartColumn,
						EndLine:     result4.EndLine,
						EndColumn:   result4.EndColumn,
						Snippet: Snippet{
							Text: result4.Value,
							Properties: Properties{
								"lineContent": strings.TrimSpace(result4.LineContent),
							},
						},
					},
				},
			},
		},
		Properties: Properties{
			"validationStatus":  string(result4.ValidationStatus),
			"cvssScore":         result4.CvssScore,
			"confluence.pageId": result4.ExtraDetails["confluence.pageId"],
			"resultId":          result4.ID,
			"severity":          result4.Severity,
			"ruleName":          RuleName4,
		},
	}
)

func TestAddSecretToFile(t *testing.T) {
	secretValue := string(`
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8
EeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe
BaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB
AoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe
ThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT
gmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip
kRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8
Tpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ
l98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+
euJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx
JPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT
9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1
4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==
-----END RSA PRIVATE KEY-----`)

	results := map[string][]*secrets.Secret{}
	report := New()
	id := "id"
	secret := &secrets.Secret{ID: id, Source: "bla", StartLine: 1, StartColumn: 0, EndLine: 1, EndColumn: 0, Value: secretValue}
	source := "directory\\rawStringAsFile.txt"
	results[source] = append(results[source], secret)
	report.SetResults(results)

	key, fileExist := report.GetResults()[source]
	if !fileExist {
		t.Errorf("key %s not added", source)
	}

	if !reflect.DeepEqual(report.GetResults(), results) {
		t.Errorf("got %+v want %+v", key, results)
	}
}

func TestWriteReportInNonExistingDir(t *testing.T) {
	report := New()

	tempDir := os.TempDir()
	path := filepath.Join(tempDir, "test_temp_dir", "sub_dir", "report.yaml")
	err := report.WriteFile([]string{path}, &config.Config{Name: "report", Version: "5"})
	if err != nil {
		t.Error(err)
	}
}

func TestGetOutputSarif(t *testing.T) {

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	tests := []struct {
		name    string
		arg     *Report
		want    []Runs
		wantErr bool
	}{
		{
			name: "two_results_same_rule_want_one_rule_in_report",
			arg: &Report{
				TotalItemsScanned: 2,
				TotalSecretsFound: 2,
				Results: map[string][]*secrets.Secret{
					"secret1": {result1},
					"secret3": {result3},
				},
			},
			wantErr: false,
			want: []Runs{
				{
					Tool: Tool{
						Driver: Driver{
							Name:            "report",
							SemanticVersion: "1",
							Rules: []*SarifRule{
								rule1Sarif,
							},
						},
					},
					Results: []Results{
						result1Sarif,
						result3Sarif,
					},
				},
			},
		},
		{
			name: "two_results_two_rules_want_two_rules_in_report",
			arg: &Report{
				TotalItemsScanned: 2,
				TotalSecretsFound: 2,
				Results: map[string][]*secrets.Secret{
					"secret1": {result1},
					"secret2": {result2},
				},
			},
			wantErr: false,
			want: []Runs{
				{
					Tool: Tool{
						Driver: Driver{
							Name:            "report",
							SemanticVersion: "1",
							Rules: []*SarifRule{
								rule1Sarif,
								rule2Sarif,
							},
						},
					},
					Results: []Results{
						result1Sarif,
						result2Sarif,
					},
				},
			},
		},
		{
			name: "includes confluence.pageId in sarif result properties",
			arg: &Report{
				TotalItemsScanned: 1,
				TotalSecretsFound: 1,
				Results: map[string][]*secrets.Secret{
					"secret1": {result4},
				},
			},
			wantErr: false,
			want: []Runs{
				{
					Tool: Tool{
						Driver: Driver{
							Name:            "report",
							SemanticVersion: "1",
							Rules: []*SarifRule{
								rule4Sarif,
							},
						},
					},
					Results: []Results{
						result4Sarif,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.arg.GetOutput(sarifFormat, &config.Config{Name: "report", Version: "1"})
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			var gotReport Sarif
			err = json.Unmarshal([]byte(got), &gotReport)
			assert.Nil(t, err)
			SortSarifReports(&gotReport, &Sarif{Runs: tt.want})
			assert.Equal(t, tt.want, gotReport.Runs)
		})
	}
}

// SortProject Sorts two sarif reports
func SortSarifReports(run1, run2 *Sarif) {
	// Sort Rules
	SortRules(run1.Runs[0].Tool.Driver.Rules, run2.Runs[0].Tool.Driver.Rules)
	SortResults(run1.Runs[0].Results, run2.Runs[0].Results)

}

func SortRules(rules1, rules2 []*SarifRule) {
	// Sort both slices
	sort.Slice(rules1, func(i, j int) bool {
		return rules1[i].ID < rules1[j].ID
	})
	sort.Slice(rules2, func(i, j int) bool {
		return rules2[i].ID < rules2[j].ID
	})
}

func SortResults(results1, results2 []Results) {
	// Sort both slices
	sort.Slice(results1, func(i, j int) bool {
		return results1[i].Message.Text < results1[j].Message.Text
	})
	sort.Slice(results2, func(i, j int) bool {
		return results2[i].Message.Text < results2[j].Message.Text
	})
}

func TestGetOutputYAML(t *testing.T) {
	testCases := []struct {
		name   string
		report *Report
	}{{
		name: "No secrets found",
		report: &Report{
			TotalItemsScanned: 5,
			TotalSecretsFound: 0,
			Results:           map[string][]*secrets.Secret{},
		},
	},
		{
			name: "Single real secret in hardcodedPassword.go",
			report: &Report{
				TotalItemsScanned: 1,
				TotalSecretsFound: 1,
				Results: map[string][]*secrets.Secret{
					"c6490d749fd4670fde969011d99ea5c4c4b1c0d7": {
						{
							ID:               "c6490d749fd4670fde969011d99ea5c4c4b1c0d7",
							Source:           "..\\2ms\\engine\\rules\\hardcodedPassword.go",
							RuleName:         "generic-api-key",
							RuleID:           "f0872990-61ab-4e55-b92a-d627dc1bc066",
							RuleCategory:     "API Access",
							StartLine:        45,
							EndLine:          45,
							LineContent:      "value",
							StartColumn:      8,
							EndColumn:        64,
							Value:            "value",
							ValidationStatus: "",
							Severity:         "High",
							CvssScore:        8.2,
							RuleDescription:  "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
						},
					},
				},
			},
		},
		{
			name: "Multiple real JWT secrets in jwt.txt",
			report: &Report{
				TotalItemsScanned: 2,
				TotalSecretsFound: 2,
				Results: map[string][]*secrets.Secret{
					"12fd8706491196cbfbdddd2fdcd650ed842dd963": {
						{
							ID:               "12fd8706491196cbfbdddd2fdcd650ed842dd963",
							Source:           "..\\2ms\\pkg\\testData\\secrets\\jwt.txt",
							RuleName:         "Jwt",
							RuleID:           "0fc98133-a57b-4e08-9990-60952d4a82df",
							RuleCategory:     "General",
							StartLine:        1,
							EndLine:          1,
							LineContent:      "line content",
							StartColumn:      129,
							EndColumn:        232,
							Value:            "value",
							ValidationStatus: "",
							Severity:         "Medium",
							CvssScore:        8.2,
							RuleDescription:  "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
							ExtraDetails: map[string]interface{}{
								"secretDetails": map[string]interface{}{
									"name": "mockName2",
									"sub":  "mockSub2",
								},
							},
						},
						{
							ID:               "12fd8706491196cbfbdddd2fdcd650ed842dd963",
							Source:           "..\\2ms\\pkg\\testData\\secrets\\jwt.txt",
							RuleName:         "Jwt",
							RuleID:           "0fc98133-a57b-4e08-9990-60952d4a82df",
							RuleCategory:     "General",
							StartLine:        2,
							EndLine:          2,
							LineContent:      "line Content",
							StartColumn:      64,
							EndColumn:        166,
							Value:            "value",
							ValidationStatus: "",
							CvssScore:        8.2,
							Severity:         "Low",
							RuleDescription:  "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
							ExtraDetails: map[string]interface{}{
								"secretDetails": map[string]interface{}{
									"name": "mockName2",
									"sub":  "mockSub2",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := tc.report.GetOutput("yaml", &config.Config{Name: "report", Version: "1"})
			assert.NoError(t, err)

			var report Report
			err = yaml.Unmarshal([]byte(output), &report)
			assert.NoError(t, err)

			assert.Equal(t, tc.report.TotalItemsScanned, report.TotalItemsScanned)
			assert.Equal(t, tc.report.TotalSecretsFound, report.TotalSecretsFound)
			assert.Equal(t, tc.report.Results, report.Results)
		})
	}
}
