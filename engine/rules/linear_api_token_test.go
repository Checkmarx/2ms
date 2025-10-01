package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinearAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LinearAPIToken validation",
			truePositives: []string{
				"linear_token: lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw",
				"linear_token: 'lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw'",
				"linearToken := `lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw`",
				"linearToken = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"System.setProperty(\"LINEAR_TOKEN\", \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\")",
				"  \"linearToken\" => \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linear_TOKEN = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linear_token: \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken := \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linear_TOKEN := \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linear_TOKEN ?= \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken=lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw",
				"$linearToken .= \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken = 'lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw'",
				"linear_TOKEN ::= \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linear_TOKEN :::= \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken=\"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"linearToken = lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw",
				"{\"config.ini\": \"LINEAR_TOKEN=lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\\nBACKUP_ENABLED=true\"}",
				"<linearToken>\n    lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\n</linearToken>",

				"string linearToken = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\";",
				"var linearToken string = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"String linearToken = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\";",
				"var linearToken = \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"",
				"{\n    \"linear_token\": \"lin_api_lt29clgxezdvugtgxq1s34jgvqgwuz7rz4jd4jiw\"\n}",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(LinearAPIToken())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
