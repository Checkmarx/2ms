package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEasypostAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "EasyPost validation",
			truePositives: []string{
				"EZAKToken = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAKToken=EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC",
				"<EZAKToken>\n    EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\n</EZAKToken>",
				"System.setProperty(\"EZAK_TOKEN\", \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\")",
				"EZAK_TOKEN := \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAK_TOKEN ?= \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"{\"config.ini\": \"EZAK_TOKEN=EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\\nBACKUP_ENABLED=true\"}",
				"EZAK_token: EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC",
				"EZAK_token: 'EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC'",
				"string EZAKToken = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\";",
				"EZAKToken := `EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC`",
				"String EZAKToken = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\";",
				"var EZAKToken = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"  \"EZAKToken\" => \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAKToken = EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC",
				"EZAKToken = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAK_TOKEN = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAK_TOKEN :::= \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"{\n    \"EZAK_token\": \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"\n}",
				"EZAK_token: \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"var EZAKToken string = \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAKToken := \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"$EZAKToken .= \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAKToken = 'EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC'",
				"EZAK_TOKEN ::= \"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",
				"EZAKToken=\"EZAKE9F4EvBnXB2Pr0Rd0NPHpsenHy7iwMli0NeUjzg25jhl7NWUjuitzC\"",

				"EZAKQUWxFhB05riqccjSSBoVzCyQinFc2D90rbItTY3gRSn6bcwTEmEzgY",
				"example.com?t=EZAKQUWxFhB05riqccjSSBoVzCyQinFc2D90rbItTY3gRSn6bcwTEmEzgY&q=1",
			},
			falsePositives: []string{
				// random base64 encoded string
				`...6wqX6fNUXA/rYqRvfQ+EZAKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6...`, // gitleaks:allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(EasyPost())
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
