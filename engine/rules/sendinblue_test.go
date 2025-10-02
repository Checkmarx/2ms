package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendInBlueAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SendInBlueAPIToken validation",
			truePositives: []string{
				"sendinblueToken = \"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\"",
				"{\n    \"sendinblue_token\": \"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\"\n}",
				"String sendinblueToken = \"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\";",
				"sendinblueToken = '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'",
				"sendinblue_TOKEN = \"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\"",
				"sendinblue_TOKEN :::= \"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\"",
				"sendinblueToken=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",
				"sendinblue_token: \"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\"",
				"var sendinblueToken = \"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\"",
				"$sendinblueToken .= \"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\"",
				"  \"sendinblueToken\" => \"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\"",
				"sendinblue_TOKEN := \"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\"",
				"sendinblueToken=\"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\"",
				"sendinblue_token: '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'",
				"string sendinblueToken = \"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\";",
				"sendinblueToken := \"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\"",
				"sendinblueToken := `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`",
				"sendinblueToken = \"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\"",
				"System.setProperty(\"SENDINBLUE_TOKEN\", \"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\")",
				"sendinblue_TOKEN ::= \"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\"",
				"sendinblueToken = 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",
				"{\"config.ini\": \"SENDINBLUE_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"<sendinblueToken>\n    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\n</sendinblueToken>",
				"sendinblue_token: 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",
				"var sendinblueToken string = \"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\"",
				"sendinblue_TOKEN ?= \"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\"",
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
			rule := ConvertNewRuleToGitleaksRule(SendInBlueAPIToken())
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
