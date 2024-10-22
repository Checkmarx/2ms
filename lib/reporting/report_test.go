package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/lib/config"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/stretchr/testify/assert"
)

var (
	ruleID1 = "ruleID1"
	ruleID2 = "ruleID2"
	result1 = &secrets.Secret{
		ID:               "ID1",
		Source:           "file1",
		RuleID:           ruleID1,
		StartLine:        150,
		EndLine:          150,
		LineContent:      "line content",
		StartColumn:      31,
		EndColumn:        150,
		Value:            "value",
		ValidationStatus: secrets.ValidResult,
		RuleDescription:  "Rule Description",
	}
	result2 = &secrets.Secret{
		ID:               "ID2",
		Source:           "file2",
		RuleID:           "ruleID1",
		StartLine:        10,
		EndLine:          10,
		LineContent:      "line content2",
		StartColumn:      41,
		EndColumn:        160,
		Value:            "value 2",
		ValidationStatus: secrets.InvalidResult,
		RuleDescription:  "Rule Description",
	}
	// this result has a different rule than 1 and 2
	result3 = &secrets.Secret{
		ID:               "ID3",
		Source:           "file3",
		RuleID:           ruleID2,
		StartLine:        16,
		EndLine:          16,
		LineContent:      "line content3",
		StartColumn:      11,
		EndColumn:        130,
		Value:            "value 3",
		ValidationStatus: secrets.UnknownResult,
		RuleDescription:  "Rule Description2",
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
	report := Report{len(results), 1, results}
	secret := &secrets.Secret{Source: "bla", StartLine: 1, StartColumn: 0, EndLine: 1, EndColumn: 0, Value: secretValue}
	source := "directory\\rawStringAsFile.txt"

	report.Results[source] = append(report.Results[source], secret)

	key, fileExist := report.Results[source]
	if !fileExist {
		t.Errorf("key %s not added", source)
	}

	if !reflect.DeepEqual(report.Results, results) {
		t.Errorf("got %+v want %+v", key, results)
	}
}

func TestWriteReportInNonExistingDir(t *testing.T) {
	report := Init()

	tempDir := os.TempDir()
	path := filepath.Join(tempDir, "test_temp_dir", "sub_dir", "report.yaml")
	err := report.WriteFile([]string{path}, &config.Config{Name: "report", Version: "5"})
	if err != nil {
		t.Error(err)
	}

	os.RemoveAll(filepath.Join(tempDir, "test_temp_dir"))
}

func TestGetOutputSarif(t *testing.T) {
	tests := []struct {
		name    string
		arg     Report
		want    []Runs
		wantErr bool
	}{
		{
			name: "two_results_same_rule_want_one_rule_in_report",
			arg: Report{
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
								{ID: "ruleID1",
									FullDescription: &Message{
										Text: result1.RuleDescription,
									},
								},
							},
						},
					},
					Results: []Results{
						{
							Message: Message{
								Text: messageText(result1.RuleID, result1.Source),
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
							},
						},
						{
							Message: Message{
								Text: messageText(result2.RuleID, result2.Source),
							},
							RuleId: ruleID1,
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
							},
						},
					},
				},
			},
		},
		{
			name: "two_results_same_rule_want_two_rules_in_report",
			arg: Report{
				TotalItemsScanned: 2,
				TotalSecretsFound: 2,
				Results: map[string][]*secrets.Secret{
					"secret1": {result1},
					"secret2": {result3},
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
								{ID: ruleID1,
									FullDescription: &Message{
										Text: result1.RuleDescription,
									},
								},
								{ID: ruleID2,
									FullDescription: &Message{
										Text: result3.RuleDescription,
									},
								},
							},
						},
					},
					Results: []Results{
						{
							Message: Message{
								Text: messageText(result1.RuleID, result1.Source),
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
							},
						},
						{
							Message: Message{
								Text: messageText(result3.RuleID, result3.Source),
							},
							RuleId: ruleID2,
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
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.arg.getOutput(sarifFormat, &config.Config{Name: "report", Version: "1"})
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			var gotReport Sarif
			err = json.Unmarshal([]byte(got), &gotReport)
			assert.Equal(t, tt.want, gotReport.Runs)
		})
	}
}
