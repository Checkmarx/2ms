package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenaiAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "OpenAI validation",
			truePositives: []string{
				"{\n    \"openaiApiKey_token\": \"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\"\n}",
				"openaiApiKey_token: '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'",
				"openaiApiKey_token: \"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\"",
				"string openaiApiKeyToken = \"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\";",
				"var openaiApiKeyToken string = \"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\"",
				"var openaiApiKeyToken = \"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\"",
				"$openaiApiKeyToken .= \"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\"",
				"  \"openaiApiKeyToken\" => \"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\"",
				"openaiApiKeyToken = \"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\"",
				"openaiApiKeyToken=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",
				"openaiApiKeyToken := \"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\"",
				"openaiApiKey_TOKEN := \"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\"",
				"openaiApiKey_TOKEN :::= \"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\"",
				"{\"config.ini\": \"OPENAIAPIKEY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"<openaiApiKeyToken>\n    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\n</openaiApiKeyToken>",
				"openaiApiKey_token: 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",
				"String openaiApiKeyToken = \"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\";",
				"openaiApiKeyToken = \"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\"",
				"System.setProperty(\"OPENAIAPIKEY_TOKEN\", \"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\")",
				"openaiApiKey_TOKEN ?= \"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\"",
				"openaiApiKeyToken=\"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\"",
				"openaiApiKeyToken = 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",
				"openaiApiKeyToken := `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`",
				"openaiApiKeyToken = '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'",
				"openaiApiKey_TOKEN = \"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\"",
				"openaiApiKey_TOKEN ::= \"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\"",
				"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",
				"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",
				"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",
				"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",
				"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",
				"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",
				"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",
				"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",
				"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",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(OpenAI())
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
