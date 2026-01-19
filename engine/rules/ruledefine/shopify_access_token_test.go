package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShopifyAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ShopifyAccessToken validation",
			truePositives: []string{
				"shopifyToken = \"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\"",
				"shopify_token: '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'",
				"string shopifyToken = \"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\";",
				"shopifyToken := \"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\"",
				"$shopifyToken .= \"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\"",
				"  \"shopifyToken\" => \"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\"",
				"shopify_TOKEN ?= \"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\"",
				"shopifyToken=\"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\"",
				"shopifyToken=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",
				"shopify_token: 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",
				"shopifyToken := `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`",
				"shopifyToken = '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'",
				"shopify_TOKEN = \"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\"",
				"shopify_TOKEN := \"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\"",
				"shopify_TOKEN ::= \"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\"",
				"{\n    \"shopify_token\": \"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\"\n}",
				"{\"config.ini\": \"SHOPIFY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"<shopifyToken>\n    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\n</shopifyToken>",
				"var shopifyToken string = \"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\"",
				"String shopifyToken = \"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\";",
				"var shopifyToken = \"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\"",
				"shopifyToken = \"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\"",
				"System.setProperty(\"SHOPIFY_TOKEN\", \"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\")",
				"shopifyToken = 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",
				"shopify_token: \"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\"",
				"shopify_TOKEN :::= \"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\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(ShopifyAccessToken())
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
