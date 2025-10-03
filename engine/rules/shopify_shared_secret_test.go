package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShopifySharedSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ShopifySharedSecret validation",
			truePositives: []string{
				"shopify_TOKEN ::= \"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\"",
				"<shopifyToken>\n    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\n</shopifyToken>",
				"shopify_token: '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'",
				"shopify_token: \"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\"",
				"var shopifyToken = \"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\"",
				"shopifyToken = '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'",
				"shopifyToken = \"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\"",
				"System.setProperty(\"SHOPIFY_TOKEN\", \"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\")",
				"shopify_TOKEN :::= \"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\"",
				"{\n    \"shopify_token\": \"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\"\n}",
				"shopifyToken := \"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\"",
				"$shopifyToken .= \"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\"",
				"shopify_TOKEN ?= \"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\"",
				"shopifyToken=\"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\"",
				"shopifyToken = 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",
				"{\"config.ini\": \"SHOPIFY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"var shopifyToken string = \"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\"",
				"shopifyToken := `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`",
				"shopify_TOKEN = \"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\"",
				"shopify_TOKEN := \"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\"",
				"shopifyToken = \"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\"",
				"shopifyToken=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",
				"shopify_token: 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",
				"string shopifyToken = \"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\";",
				"String shopifyToken = \"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\";",
				"  \"shopifyToken\" => \"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\"",
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
			rule := ConvertNewRuleToGitleaksRule(ShopifySharedSecret())
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
