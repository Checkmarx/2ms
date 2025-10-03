package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLaunchDarklyAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LaunchDarklyAccessToken validation",
			truePositives: []string{
				"var launchdarklyToken string = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"String launchdarklyToken = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\";",
				"launchdarkly_TOKEN :::= \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarkly_token: \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken := `tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv`",
				"System.setProperty(\"LAUNCHDARKLY_TOKEN\", \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\")",
				"  \"launchdarklyToken\" => \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarkly_TOKEN = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarkly_TOKEN ::= \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"<launchdarklyToken>\n    tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\n</launchdarklyToken>",
				"launchdarklyToken := \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"var launchdarklyToken = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarkly_TOKEN ?= \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken=\"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken=tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv",
				"{\"config.ini\": \"LAUNCHDARKLY_TOKEN=tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\\nBACKUP_ENABLED=true\"}",
				"launchdarkly_token: tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv",
				"string launchdarklyToken = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\";",
				"$launchdarklyToken .= \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken = 'tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv'",
				"launchdarkly_TOKEN := \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken = \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"",
				"launchdarklyToken = tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv",
				"{\n    \"launchdarkly_token\": \"tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv\"\n}",
				"launchdarkly_token: 'tylxkq-2bde9=vyyq3c72klvi86qwhud3i2s8dbv'",
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
			rule := ConvertNewRuleToGitleaksRule(LaunchDarklyAccessToken())
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
