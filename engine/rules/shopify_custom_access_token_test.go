package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShopifyCustomAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ShopifyCustomAccessToken validation",
			truePositives: []string{
				"shopifyToken = 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",
				"{\"config.ini\": \"SHOPIFY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"  \"shopifyToken\" => \"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\"",
				"shopify_TOKEN := \"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\"",
				"shopifyToken=\"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\"",
				"shopifyToken = \"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\"",
				"<shopifyToken>\n    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\n</shopifyToken>",
				"shopify_token: \"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\"",
				"String shopifyToken = \"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\";",
				"System.setProperty(\"SHOPIFY_TOKEN\", \"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\")",
				"shopify_TOKEN ::= \"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\"",
				"shopify_TOKEN :::= \"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\"",
				"shopifyToken=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",
				"shopify_token: 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",
				"shopify_token: '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'",
				"var shopifyToken string = \"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\"",
				"shopifyToken := `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`",
				"$shopifyToken .= \"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\"",
				"shopifyToken = \"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\"",
				"shopify_TOKEN ?= \"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\"",
				"{\n    \"shopify_token\": \"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\"\n}",
				"string shopifyToken = \"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\";",
				"shopifyToken := \"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\"",
				"var shopifyToken = \"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\"",
				"shopifyToken = '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'",
				"shopify_TOKEN = \"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\"",
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
			rule := ConvertNewRuleToGitleaksRule(ShopifyCustomAccessToken())
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
