package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdobeClientID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "AdobeClientID validation",
			truePositives: []string{
				"adobeToken = '772d138b3a327a5879a65b01f6fe2d4c'",
				"adobe_TOKEN := \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobe_token: 772d138b3a327a5879a65b01f6fe2d4c",
				"adobe_token: '772d138b3a327a5879a65b01f6fe2d4c'",
				"var adobeToken string = \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"$adobeToken .= \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobeToken = \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"System.setProperty(\"ADOBE_TOKEN\"," + " \"772d138b3a327a5879a65b01f6fe2d4c\")",
				"adobe_TOKEN = \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobe_TOKEN :::= \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"{\n    \"adobe_token\": \"772d138b3a327a5879a65b01f6fe2d4c\"\n}",
				"<adobeToken>\n    772d138b3a327a5879a65b01f6fe2d4c\n</adobeToken>",
				"adobeToken := `772d138b3a327a5879a65b01f6fe2d4c`",
				"adobeToken=772d138b3a327a5879a65b01f6fe2d4c",
				"adobeToken = 772d138b3a327a5879a65b01f6fe2d4c",
				"adobe_token: \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobeToken := \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"  \"adobeToken\" => \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobe_TOKEN ::= \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobe_TOKEN ?= \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobeToken=\"772d138b3a327a5879a65b01f6fe2d4c\"",
				"adobeToken = \"772d138b3a327a5879a65b01f6fe2d4c\"",
				"{\"config.ini\": \"ADOBE_TOKEN=772d138b3a327a5879a65b01f6fe2d4c\\nBACKUP_ENABLED=true\"}",
				"string adobeToken = \"772d138b3a327a5879a65b01f6fe2d4c\";",
				"String adobeToken = \"772d138b3a327a5879a65b01f6fe2d4c\";",
				"var adobeToken = \"772d138b3a327a5879a65b01f6fe2d4c\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(AdobeClientID())
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
