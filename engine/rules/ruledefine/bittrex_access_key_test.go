package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBittrexAccessKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "BittrexAccessKey validation",
			truePositives: []string{

				"bittrex_TOKEN :::= \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrex_TOKEN ?= \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrexToken=jz08yzvdc1b2jm1eo53yr1q454sy7yxh",
				"bittrexToken = jz08yzvdc1b2jm1eo53yr1q454sy7yxh",
				"bittrex_token: jz08yzvdc1b2jm1eo53yr1q454sy7yxh",
				"var bittrexToken string = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrexToken := \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"String bittrexToken = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\";",
				"bittrexToken = 'jz08yzvdc1b2jm1eo53yr1q454sy7yxh'",
				"bittrex_TOKEN := \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"{\"config.ini\": \"BITTREX_TOKEN=jz08yzvdc1b2jm1eo53yr1q454sy7yxh\\nBACKUP_ENABLED=true\"}",
				"<bittrexToken>\n    jz08yzvdc1b2jm1eo53yr1q454sy7yxh\n</bittrexToken>",
				"var bittrexToken = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"$bittrexToken .= \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrexToken = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrex_TOKEN = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrex_TOKEN ::= \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrexToken=\"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"bittrexToken = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"{\n    \"bittrex_token\": \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"\n}",
				"bittrex_token: 'jz08yzvdc1b2jm1eo53yr1q454sy7yxh'",
				"bittrexToken := `jz08yzvdc1b2jm1eo53yr1q454sy7yxh`",
				"System.setProperty(\"BITTREX_TOKEN\", \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\")",
				"bittrex_token: \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
				"string bittrexToken = \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\";",
				"  \"bittrexToken\" => \"jz08yzvdc1b2jm1eo53yr1q454sy7yxh\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(BittrexAccessKey())
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
