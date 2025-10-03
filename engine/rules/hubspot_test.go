package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHubspotAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "HubSpot validation",
			truePositives: []string{
				"string hubspotToken = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\";",
				"hubspotToken = '1b16c9a7-049a-f99e-2ede-c4832c8246bd'",
				"hubspotToken = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"{\"config.ini\": \"HUBSPOT_TOKEN=1b16c9a7-049a-f99e-2ede-c4832c8246bd\\nBACKUP_ENABLED=true\"}",
				"<hubspotToken>\n    1b16c9a7-049a-f99e-2ede-c4832c8246bd\n</hubspotToken>",
				"hubspotToken := \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"String hubspotToken = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\";",
				"hubspot_TOKEN := \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspot_TOKEN ::= \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspot_token: 1b16c9a7-049a-f99e-2ede-c4832c8246bd",
				"var hubspotToken string = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspotToken := `1b16c9a7-049a-f99e-2ede-c4832c8246bd`",
				"$hubspotToken .= \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"System.setProperty(\"HUBSPOT_TOKEN\", \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\")",
				"  \"hubspotToken\" => \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspot_TOKEN = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspot_TOKEN :::= \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspotToken=1b16c9a7-049a-f99e-2ede-c4832c8246bd",
				"hubspotToken = 1b16c9a7-049a-f99e-2ede-c4832c8246bd",
				"var hubspotToken = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspot_TOKEN ?= \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspotToken=\"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"hubspotToken = \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				"{\n    \"hubspot_token\": \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"\n}",
				"hubspot_token: '1b16c9a7-049a-f99e-2ede-c4832c8246bd'",
				"hubspot_token: \"1b16c9a7-049a-f99e-2ede-c4832c8246bd\"",
				`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,
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
			rule := ConvertNewRuleToGitleaksRule(HubSpot())
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
