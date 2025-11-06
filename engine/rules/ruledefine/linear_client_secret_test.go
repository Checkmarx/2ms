package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinearClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LinearClientSecret validation",
			truePositives: []string{
				"$linearToken .= \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"System.setProperty(\"LINEAR_TOKEN\", \"eda47aab35617d8daf7cf127a7dc8f04\")",
				"linear_TOKEN = \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linearToken=eda47aab35617d8daf7cf127a7dc8f04",
				"linearToken := \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"var linearToken = \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linearToken = \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linearToken = eda47aab35617d8daf7cf127a7dc8f04",
				"  \"linearToken\" => \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linear_TOKEN := \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linear_TOKEN ::= \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linear_TOKEN :::= \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linear_TOKEN ?= \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linearToken = \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"{\n    \"linear_token\": \"eda47aab35617d8daf7cf127a7dc8f04\"\n}",
				"{\"config.ini\": \"LINEAR_TOKEN=eda47aab35617d8daf7cf127a7dc8f04\\nBACKUP_ENABLED=true\"}",
				"string linearToken = \"eda47aab35617d8daf7cf127a7dc8f04\";",
				"var linearToken string = \"eda47aab35617d8daf7cf127a7dc8f04\"",
				"linearToken := `eda47aab35617d8daf7cf127a7dc8f04`",
				"String linearToken = \"eda47aab35617d8daf7cf127a7dc8f04\";",
				"linearToken = 'eda47aab35617d8daf7cf127a7dc8f04'",
				"linearToken=\"eda47aab35617d8daf7cf127a7dc8f04\"",
				"<linearToken>\n    eda47aab35617d8daf7cf127a7dc8f04\n</linearToken>",
				"linear_token: eda47aab35617d8daf7cf127a7dc8f04",
				"linear_token: 'eda47aab35617d8daf7cf127a7dc8f04'",
				"linear_token: \"eda47aab35617d8daf7cf127a7dc8f04\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(LinearClientSecret())
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
