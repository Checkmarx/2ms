package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFinnhubAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FinnhubAccessToken validation",
			truePositives: []string{
				"finnhubToken = 2khvqovszqxnxp6n8a6l",
				"<finnhubToken>\n    2khvqovszqxnxp6n8a6l\n</finnhubToken>",
				"var finnhubToken string = \"2khvqovszqxnxp6n8a6l\"",
				"  \"finnhubToken\" => \"2khvqovszqxnxp6n8a6l\"",
				"finnhubToken = \"2khvqovszqxnxp6n8a6l\"",
				"finnhub_token: '2khvqovszqxnxp6n8a6l'",
				"string finnhubToken = \"2khvqovszqxnxp6n8a6l\";",
				"finnhubToken := \"2khvqovszqxnxp6n8a6l\"",
				"String finnhubToken = \"2khvqovszqxnxp6n8a6l\";",
				"var finnhubToken = \"2khvqovszqxnxp6n8a6l\"",
				"{\n    \"finnhub_token\": \"2khvqovszqxnxp6n8a6l\"\n}",
				"{\"config.ini\": \"FINNHUB_TOKEN=2khvqovszqxnxp6n8a6l\\nBACKUP_ENABLED=true\"}",
				"finnhub_token: \"2khvqovszqxnxp6n8a6l\"",
				"finnhubToken := `2khvqovszqxnxp6n8a6l`",
				"finnhubToken = '2khvqovszqxnxp6n8a6l'",
				"finnhub_TOKEN :::= \"2khvqovszqxnxp6n8a6l\"",
				"finnhub_token: 2khvqovszqxnxp6n8a6l",
				"$finnhubToken .= \"2khvqovszqxnxp6n8a6l\"",
				"finnhubToken = \"2khvqovszqxnxp6n8a6l\"",
				"System.setProperty(\"FINNHUB_TOKEN\", \"2khvqovszqxnxp6n8a6l\")",
				"finnhub_TOKEN = \"2khvqovszqxnxp6n8a6l\"",
				"finnhub_TOKEN := \"2khvqovszqxnxp6n8a6l\"",
				"finnhub_TOKEN ::= \"2khvqovszqxnxp6n8a6l\"",
				"finnhub_TOKEN ?= \"2khvqovszqxnxp6n8a6l\"",
				"finnhubToken=\"2khvqovszqxnxp6n8a6l\"",
				"finnhubToken=2khvqovszqxnxp6n8a6l",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(FinnhubAccessToken())
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
