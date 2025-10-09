package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFinicityClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FinicityClientSecret validation",
			truePositives: []string{
				"finicityToken=\"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken = 'nc9l4ze4m4rmepbn9oyc'",
				"System.setProperty(\"FINICITY_TOKEN\", \"nc9l4ze4m4rmepbn9oyc\")",
				"finicity_TOKEN :::= \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken = nc9l4ze4m4rmepbn9oyc",
				"{\n    \"finicity_token\": \"nc9l4ze4m4rmepbn9oyc\"\n}",
				"{\"config.ini\": \"FINICITY_TOKEN=nc9l4ze4m4rmepbn9oyc\\nBACKUP_ENABLED=true\"}",
				"finicity_token: 'nc9l4ze4m4rmepbn9oyc'",
				"finicity_token: \"nc9l4ze4m4rmepbn9oyc\"",
				"var finicityToken = \"nc9l4ze4m4rmepbn9oyc\"",
				"$finicityToken .= \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken = \"nc9l4ze4m4rmepbn9oyc\"",
				"<finicityToken>\n    nc9l4ze4m4rmepbn9oyc\n</finicityToken>",
				"finicity_token: nc9l4ze4m4rmepbn9oyc",
				"string finicityToken = \"nc9l4ze4m4rmepbn9oyc\";",
				"String finicityToken = \"nc9l4ze4m4rmepbn9oyc\";",
				"  \"finicityToken\" => \"nc9l4ze4m4rmepbn9oyc\"",
				"finicity_TOKEN = \"nc9l4ze4m4rmepbn9oyc\"",
				"finicity_TOKEN ::= \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken = \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken=nc9l4ze4m4rmepbn9oyc",
				"var finicityToken string = \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken := \"nc9l4ze4m4rmepbn9oyc\"",
				"finicityToken := `nc9l4ze4m4rmepbn9oyc`",
				"finicity_TOKEN := \"nc9l4ze4m4rmepbn9oyc\"",
				"finicity_TOKEN ?= \"nc9l4ze4m4rmepbn9oyc\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(FinicityClientSecret())
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
