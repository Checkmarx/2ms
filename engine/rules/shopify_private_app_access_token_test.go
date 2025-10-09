package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShopifyPrivateAppAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ShopifyPrivateAppAccessToken validation",
			truePositives: []string{
				"shopifyToken = \"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\"",
				"  \"shopifyToken\" => \"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\"",
				"shopify_TOKEN = \"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\"",
				"shopifyToken=\"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\"",
				"<shopifyToken>\n    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\n</shopifyToken>",
				"shopifyToken = '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'",
				"System.setProperty(\"SHOPIFY_TOKEN\", \"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\")",
				"shopify_TOKEN := \"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\"",
				"shopify_TOKEN ::= \"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\"",
				"{\"config.ini\": \"SHOPIFY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"shopify_token: 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",
				"string shopifyToken = \"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\";",
				"shopifyToken := \"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\"",
				"shopifyToken := `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`",
				"$shopifyToken .= \"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\"",
				"shopify_TOKEN :::= \"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\"",
				"shopify_token: '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'",
				"shopify_token: \"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\"",
				"String shopifyToken = \"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\";",
				"var shopifyToken = \"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\"",
				"shopify_TOKEN ?= \"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\"",
				"shopifyToken = \"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\"",
				"shopifyToken=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",
				"shopifyToken = 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",
				"{\n    \"shopify_token\": \"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\"\n}",
				"var shopifyToken string = \"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\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(ShopifyPrivateAppAccessToken())
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
