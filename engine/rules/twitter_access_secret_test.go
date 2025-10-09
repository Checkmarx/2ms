package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwitterAccessSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TwitterAccessSecret validation",
			truePositives: []string{
				"twitterToken = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitter_token: \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"$twitterToken .= \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitter_TOKEN = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitter_TOKEN ::= \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitter_TOKEN ?= \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitterToken=70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3",
				"{\n    \"twitter_token\": \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"\n}",
				"{\"config.ini\": \"TWITTER_TOKEN=70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\\nBACKUP_ENABLED=true\"}",
				"twitter_token: 70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3",
				"string twitterToken = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\";",
				"twitter_TOKEN := \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitterToken = 70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3",
				"twitter_token: '70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3'",
				"var twitterToken string = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"String twitterToken = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\";",
				"twitterToken = '70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3'",
				"twitterToken = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"  \"twitterToken\" => \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitter_TOKEN :::= \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitterToken=\"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"<twitterToken>\n    70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\n</twitterToken>",
				"twitterToken := \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"twitterToken := `70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3`",
				"var twitterToken = \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\"",
				"System.setProperty(\"TWITTER_TOKEN\", \"70zpdwviwq8pab914dc79xxmrnq2lpskjb6izj2xwaox3\")",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(TwitterAccessSecret())
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
