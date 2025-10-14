package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwitterAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TwitterAPIKey validation",
			truePositives: []string{
				"twitter_TOKEN :::= \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"{\n    \"twitter_token\": \"tyzkzbpb6uzir3sz5412ygcgy\"\n}",
				"<twitterToken>\n    tyzkzbpb6uzir3sz5412ygcgy\n</twitterToken>",
				"twitter_token: \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken := `tyzkzbpb6uzir3sz5412ygcgy`",
				"twitterToken = 'tyzkzbpb6uzir3sz5412ygcgy'",
				"twitter_TOKEN := \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken=tyzkzbpb6uzir3sz5412ygcgy",
				"string twitterToken = \"tyzkzbpb6uzir3sz5412ygcgy\";",
				"var twitterToken string = \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken = \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"System.setProperty(\"TWITTER_TOKEN\", \"tyzkzbpb6uzir3sz5412ygcgy\")",
				"  \"twitterToken\" => \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitter_TOKEN ?= \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken=\"tyzkzbpb6uzir3sz5412ygcgy\"",
				"{\"config.ini\": \"TWITTER_TOKEN=tyzkzbpb6uzir3sz5412ygcgy\\nBACKUP_ENABLED=true\"}",
				"twitter_token: tyzkzbpb6uzir3sz5412ygcgy",
				"var twitterToken = \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"$twitterToken .= \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitter_TOKEN = \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitter_TOKEN ::= \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken = \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"twitterToken = tyzkzbpb6uzir3sz5412ygcgy",
				"twitter_token: 'tyzkzbpb6uzir3sz5412ygcgy'",
				"twitterToken := \"tyzkzbpb6uzir3sz5412ygcgy\"",
				"String twitterToken = \"tyzkzbpb6uzir3sz5412ygcgy\";",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(TwitterAPIKey())
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
