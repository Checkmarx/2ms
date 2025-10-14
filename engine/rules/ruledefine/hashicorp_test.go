package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashiCorpTerraform(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "HashiCorpTerraform validation",
			truePositives: []string{
				"{\n    \"hashicorpToken_token\": \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"\n}",
				"{\"config.ini\": \"HASHICORPTOKEN_TOKEN=275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\\nBACKUP_ENABLED=true\"}",
				"hashicorpToken_token: 275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0",
				"hashicorpTokenToken = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpToken_TOKEN = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpToken_TOKEN :::= \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"var hashicorpTokenToken string = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"var hashicorpTokenToken = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"$hashicorpTokenToken .= \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpTokenToken = '275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0'",
				"System.setProperty(\"HASHICORPTOKEN_TOKEN\", \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\")",
				"hashicorpToken_TOKEN ?= \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpTokenToken=\"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpTokenToken=275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0",
				"hashicorpTokenToken = 275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0",
				"<hashicorpTokenToken>\n    275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\n</hashicorpTokenToken>",
				"hashicorpToken_token: \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"string hashicorpTokenToken = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\";",
				"hashicorpTokenToken := \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpTokenToken := `275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0`",
				"hashicorpTokenToken = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpToken_token: '275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0'",
				"String hashicorpTokenToken = \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\";",
				"  \"hashicorpTokenToken\" => \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpToken_TOKEN := \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				"hashicorpToken_TOKEN ::= \"275af53921b8f9.atlasv1.52hsqvtyyer80buyzswube=h-xvvqvjaf-n9fvchn=x643ltobb0x3c7t3n0\"",
				`#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`,
			},
			falsePositives: []string{
				`token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // low entropy
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(HashiCorpTerraform())
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
