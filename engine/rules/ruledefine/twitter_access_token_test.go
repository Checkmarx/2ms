package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwitterAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TwitterAccessToken validation",
			truePositives: []string{
				"twitter_TOKEN :::= \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitterToken = \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitter_token: '519794867458713-abaD5uNbCpLid4fYXz2k'",
				"twitter_token: \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"string twitterToken = \"519794867458713-abaD5uNbCpLid4fYXz2k\";",
				"twitterToken := `519794867458713-abaD5uNbCpLid4fYXz2k`",
				"$twitterToken .= \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"  \"twitterToken\" => \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitter_TOKEN = \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitterToken = 519794867458713-abaD5uNbCpLid4fYXz2k",
				"{\"config.ini\": \"TWITTER_TOKEN=519794867458713-abaD5uNbCpLid4fYXz2k\\nBACKUP_ENABLED=true\"}",
				"var twitterToken = \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitterToken = '519794867458713-abaD5uNbCpLid4fYXz2k'",
				"twitter_TOKEN ::= \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitter_TOKEN ?= \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"{\n    \"twitter_token\": \"519794867458713-abaD5uNbCpLid4fYXz2k\"\n}",
				"twitter_token: 519794867458713-abaD5uNbCpLid4fYXz2k",
				"var twitterToken string = \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"System.setProperty(\"TWITTER_TOKEN\", \"519794867458713-abaD5uNbCpLid4fYXz2k\")",
				"twitter_TOKEN := \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitterToken=\"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"twitterToken=519794867458713-abaD5uNbCpLid4fYXz2k",
				"<twitterToken>\n    519794867458713-abaD5uNbCpLid4fYXz2k\n</twitterToken>",
				"twitterToken := \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
				"String twitterToken = \"519794867458713-abaD5uNbCpLid4fYXz2k\";",
				"twitterToken = \"519794867458713-abaD5uNbCpLid4fYXz2k\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(TwitterAccessToken())
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
