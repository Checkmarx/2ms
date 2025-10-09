package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaxmindLicenseKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MaxMindLicenseKey validation",
			truePositives: []string{
				"{\"config.ini\": \"MAXMIND_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"maxmindToken := `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`",
				"$maxmindToken .= \"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\"",
				"maxmind_TOKEN ::= \"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\"",
				"maxmind_TOKEN ?= \"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\"",
				"maxmindToken = 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",
				"string maxmindToken = \"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\";",
				"maxmindToken = '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'",
				"maxmindToken = \"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\"",
				"{\n    \"maxmind_token\": \"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\"\n}",
				"<maxmindToken>\n    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\n</maxmindToken>",
				"maxmind_token: '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'",
				"maxmind_token: \"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\"",
				"var maxmindToken string = \"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\"",
				"maxmindToken := \"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\"",
				"String maxmindToken = \"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\";",
				"var maxmindToken = \"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\"",
				"maxmind_token: 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",
				"System.setProperty(\"MAXMIND_TOKEN\", \"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\")",
				"  \"maxmindToken\" => \"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\"",
				"maxmind_TOKEN = \"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\"",
				"maxmind_TOKEN := \"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\"",
				"maxmind_TOKEN :::= \"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\"",
				"maxmindToken=\"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\"",
				"maxmindToken = \"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\"",
				"maxmindToken=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",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(MaxMindLicenseKey())
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
