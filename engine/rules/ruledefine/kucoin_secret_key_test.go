package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKucoinSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "KucoinSecretKey validation",
			truePositives: []string{
				"kucoin_token: 8fc8c878-2a2f-c45c-6b4b-dc223d433fe4",
				"kucoin_token: \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoin_TOKEN = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoin_TOKEN := \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoin_TOKEN ::= \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"string kucoinToken = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\";",
				"String kucoinToken = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\";",
				"$kucoinToken .= \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"System.setProperty(\"KUCOIN_TOKEN\", \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\")",
				"kucoinToken=8fc8c878-2a2f-c45c-6b4b-dc223d433fe4",
				"var kucoinToken string = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"var kucoinToken = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken = '8fc8c878-2a2f-c45c-6b4b-dc223d433fe4'",
				"kucoin_TOKEN :::= \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoin_TOKEN ?= \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken=\"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken = \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken = 8fc8c878-2a2f-c45c-6b4b-dc223d433fe4",
				"<kucoinToken>\n    8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\n</kucoinToken>",
				"kucoin_token: '8fc8c878-2a2f-c45c-6b4b-dc223d433fe4'",
				"kucoinToken := \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"kucoinToken := `8fc8c878-2a2f-c45c-6b4b-dc223d433fe4`",
				"  \"kucoinToken\" => \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"",
				"{\n    \"kucoin_token\": \"8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\"\n}",
				"{\"config.ini\": \"KUCOIN_TOKEN=8fc8c878-2a2f-c45c-6b4b-dc223d433fe4\\nBACKUP_ENABLED=true\"}",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(KucoinSecretKey())
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
