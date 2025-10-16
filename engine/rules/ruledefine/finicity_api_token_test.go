package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFinicityAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FinicityAPIToken validation",
			truePositives: []string{
				"finicity_token: \"a90df6822e71a865a10be28bad864171\"",
				"finicityToken := \"a90df6822e71a865a10be28bad864171\"",
				"finicityToken := `a90df6822e71a865a10be28bad864171`",
				"finicityToken = 'a90df6822e71a865a10be28bad864171'",
				"finicityToken = \"a90df6822e71a865a10be28bad864171\"",
				"  \"finicityToken\" => \"a90df6822e71a865a10be28bad864171\"",
				"finicityToken = \"a90df6822e71a865a10be28bad864171\"",
				"{\n    \"finicity_token\": \"a90df6822e71a865a10be28bad864171\"\n}",
				"string finicityToken = \"a90df6822e71a865a10be28bad864171\";",
				"var finicityToken string = \"a90df6822e71a865a10be28bad864171\"",
				"$finicityToken .= \"a90df6822e71a865a10be28bad864171\"",
				"finicity_TOKEN ::= \"a90df6822e71a865a10be28bad864171\"",
				"finicity_TOKEN ?= \"a90df6822e71a865a10be28bad864171\"",
				"<finicityToken>\n    a90df6822e71a865a10be28bad864171\n</finicityToken>",
				"String finicityToken = \"a90df6822e71a865a10be28bad864171\";",
				"var finicityToken = \"a90df6822e71a865a10be28bad864171\"",
				"System.setProperty(\"FINICITY_TOKEN\", \"a90df6822e71a865a10be28bad864171\")",
				"finicity_TOKEN := \"a90df6822e71a865a10be28bad864171\"",
				"finicityToken=\"a90df6822e71a865a10be28bad864171\"",
				"finicityToken=a90df6822e71a865a10be28bad864171",
				"finicityToken = a90df6822e71a865a10be28bad864171",
				"finicity_token: 'a90df6822e71a865a10be28bad864171'",
				"finicity_TOKEN = \"a90df6822e71a865a10be28bad864171\"",
				"finicity_TOKEN :::= \"a90df6822e71a865a10be28bad864171\"",
				"{\"config.ini\": \"FINICITY_TOKEN=a90df6822e71a865a10be28bad864171\\nBACKUP_ENABLED=true\"}",
				"finicity_token: a90df6822e71a865a10be28bad864171",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FinicityAPIToken())
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
