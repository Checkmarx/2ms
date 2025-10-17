package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwitchAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TwitchAPIToken validation",
			truePositives: []string{
				"twitchToken = 3eueu0fz1vuhjqhwzml8mfjr01ew15",
				"<twitchToken>\n    3eueu0fz1vuhjqhwzml8mfjr01ew15\n</twitchToken>",
				"twitch_token: '3eueu0fz1vuhjqhwzml8mfjr01ew15'",
				"string twitchToken = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\";",
				"var twitchToken = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"$twitchToken .= \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitch_token: \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken := \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken := `3eueu0fz1vuhjqhwzml8mfjr01ew15`",
				"String twitchToken = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\";",
				"System.setProperty(\"TWITCH_TOKEN\", \"3eueu0fz1vuhjqhwzml8mfjr01ew15\")",
				"  \"twitchToken\" => \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitch_TOKEN := \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitch_TOKEN :::= \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"{\n    \"twitch_token\": \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"\n}",
				"twitch_token: 3eueu0fz1vuhjqhwzml8mfjr01ew15",
				"var twitchToken string = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken = '3eueu0fz1vuhjqhwzml8mfjr01ew15'",
				"twitch_TOKEN = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken=\"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitchToken=3eueu0fz1vuhjqhwzml8mfjr01ew15",
				"{\"config.ini\": \"TWITCH_TOKEN=3eueu0fz1vuhjqhwzml8mfjr01ew15\\nBACKUP_ENABLED=true\"}",
				"twitchToken = \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitch_TOKEN ::= \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
				"twitch_TOKEN ?= \"3eueu0fz1vuhjqhwzml8mfjr01ew15\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(TwitchAPIToken())
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
