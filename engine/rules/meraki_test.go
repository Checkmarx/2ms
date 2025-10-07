package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCiscoMerakiAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Meraki validation",
			truePositives: []string{
				"meraki_token: 24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2",
				"var merakiToken = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"meraki_TOKEN ::= \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"meraki_TOKEN ?= \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"merakiToken=\"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"merakiToken=24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2",
				"merakiToken = 24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2",
				"$merakiToken .= \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"System.setProperty(\"MERAKI_TOKEN\", \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\")",
				"  \"merakiToken\" => \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"meraki_TOKEN :::= \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"meraki_token: '24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2'",
				"meraki_token: \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"string merakiToken = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\";",
				"merakiToken := \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"String merakiToken = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\";",
				"merakiToken = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"meraki_TOKEN := \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"{\"config.ini\": \"MERAKI_TOKEN=24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\\nBACKUP_ENABLED=true\"}",
				"<merakiToken>\n    24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\n</merakiToken>",
				"var merakiToken string = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"merakiToken := `24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2`",
				"merakiToken = '24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2'",
				"meraki_TOKEN = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"merakiToken = \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"",
				"{\n    \"meraki_token\": \"24ee9f49b0ffd468cd6cea061aeb4dc56b4da1a2\"\n}",
			},
			falsePositives: []string{
				`meraki: aaaaaaaaaa1111111111bbbbbbbbbb2222222222`,                                   // low entropy
				`meraki-api-key: acdeFf05b1a6d4c890237bf08c5e6e8d2b4d0f2e`,                           // invalid case
				`meraki: abdefghjk0123456789mnopqrstuvwx12345678`,                                    // invalid character
				`meraki_token = 5cb4a5f04cd412fe946667b17f0129ba17aeb2e0c7b5b7264efcebf7d022bfe2R21`, // invalid length
				`ReactNativeCameraKit: f15a5a04b0f6dc6073e6db0296e6ef2d8b8d2522`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(Meraki())
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
