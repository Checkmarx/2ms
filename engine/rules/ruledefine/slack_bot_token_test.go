package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackBotToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackBotToken validation",
			truePositives: []string{
				"bot_token: 'xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD'",
				"botToken := `xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD`",
				"  \"botToken\" => \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_TOKEN = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_TOKEN ?= \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_token: \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"var botToken = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"System.setProperty(\"BOT_TOKEN\", \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\")",
				"bot_TOKEN ::= \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"botToken = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_token: xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD",
				"$botToken .= \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"botToken = 'xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD'",
				"botToken = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_TOKEN := \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"bot_TOKEN :::= \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"botToken = xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD",
				"{\n    \"bot_token\": \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"\n}",
				"{\"config.ini\": \"BOT_TOKEN=xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\\nBACKUP_ENABLED=true\"}",
				"<botToken>\n    xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\n</botToken>",
				"string botToken = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\";",
				"var botToken string = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"botToken := \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"String botToken = \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\";",
				"botToken=\"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"botToken=xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD",
				"\"bot_token1\": \"xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD\"",
				"\"bot_token2\": \"xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS\"",
				"\"bot_token3\": \"xoxb-4614724432022-5152386766518-O5WzjWGLG0wcCm2WPrjEmnys\"",
				"\"bot_token4\": \"xoxb-8353272146787-835327214678-sfd98pslcwb2xqkpq4yizzii\"",
			},
			falsePositives: []string{
				"xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx",
				"xoxb-xxx",
				"xoxb-12345-abcd234",
				"xoxb-xoxb-my-bot-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SlackBotToken())
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
