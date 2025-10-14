package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackLegacyBotToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackLegacyBotToken validation",
			truePositives: []string{
				"slackToken=xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"string slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\";",
				"slackToken = 'xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1'",
				"slack_TOKEN = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN :::= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken=\"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"{\n    \"slack_token\": \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"\n}",
				"{\"config.ini\": \"SLACK_TOKEN=xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\\nBACKUP_ENABLED=true\"}",
				"<slackToken>\n    xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\n</slackToken>",
				"slack_token: xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"slackToken := \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken := `xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1`",
				"slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken = xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"var slackToken string = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"System.setProperty(\"SLACK_TOKEN\", \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\")",
				"  \"slackToken\" => \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN := \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN ::= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN ?= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_token: 'xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1'",
				"slack_token: \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"String slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\";",
				"var slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"$slackToken .= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"\"bot_token1\": \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"\"bot_token2\": \"xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP\"",
				"\"bot_token3\": \"xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1\"",
				"\"bot_token4\": \"xoxb-123456789012-Xw937qtWSXJss1lFaKe\"",
				"\"bot_token5\": \"xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS\"",
				"\"bot_token6\": \"xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi\"",
				"\"bot_token7\": \"xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK\"",
				"\"bot_token8\": \"xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI\"",
				"\"bot_token9\": \"xoxb-50014434-slacktokenx29U9X1bQ\"",
				"\"bot_token10\": \"xoxb-6036579657-ks3e7l1cfdqnlt5zdmsb9suj",
				"\"bot_token11\": \"xoxb-603657965729-ks3e7l1cfdqnlt5zdmsb9su",
			},
			falsePositives: []string{
				"xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
				"xoxb-Slack_BOT_TOKEN",
				"xoxb-abcdef-abcdef",
				// "xoxb-0000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SlackLegacyBotToken())
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
