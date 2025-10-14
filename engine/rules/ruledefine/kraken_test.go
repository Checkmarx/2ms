package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKrakenAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "KrakenAccessToken validation",
			truePositives: []string{
				"krakenToken=\"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"krakenToken = 0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6",
				"kraken_token: 0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6",
				"string krakenToken = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\";",
				"krakenToken := \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"String krakenToken = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\";",
				"var krakenToken = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"krakenToken = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"krakenToken=0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6",
				"{\"config.ini\": \"KRAKEN_TOKEN=0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\\nBACKUP_ENABLED=true\"}",
				"kraken_token: \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"krakenToken := `0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6`",
				"kraken_TOKEN ?= \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"{\n    \"kraken_token\": \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"\n}",
				"kraken_token: '0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6'",
				"var krakenToken string = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"$krakenToken .= \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"  \"krakenToken\" => \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"kraken_TOKEN := \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"kraken_TOKEN ::= \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"krakenToken = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"<krakenToken>\n    0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\n</krakenToken>",
				"krakenToken = '0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6'",
				"System.setProperty(\"KRAKEN_TOKEN\", \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\")",
				"kraken_TOKEN = \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
				"kraken_TOKEN :::= \"0zdooqculvf8/mn-chatgivcodanxysp2hd7q4u0v3j3_q67=l_08z49xx96g4h51lylr3fv=05w_7u6\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(KrakenAccessToken())
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
