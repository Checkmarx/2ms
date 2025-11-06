package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackLegacyWorkspaceToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackLegacyWorkspaceToken validation",
			truePositives: []string{
				"slackToken=\"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"{\n    \"slack_token\": \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"\n}",
				"var slackToken string = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken := \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken = 'xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c'",
				"System.setProperty(\"SLACK_TOKEN\", \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\")",
				"slack_TOKEN = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slack_TOKEN ::= \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken=xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c",
				"slackToken = xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c",
				"{\"config.ini\": \"SLACK_TOKEN=xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\\nBACKUP_ENABLED=true\"}",
				"<slackToken>\n    xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\n</slackToken>",
				"slack_token: 'xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c'",
				"string slackToken = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\";",
				"slack_TOKEN := \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slack_TOKEN :::= \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slack_token: \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken := `xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c`",
				"String slackToken = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\";",
				"$slackToken .= \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slack_TOKEN ?= \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slack_token: xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c",
				"var slackToken = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"slackToken = \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"  \"slackToken\" => \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"\"access_token\": \"xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c\"",
				"\"access_token1\": \"xoxa-7-bykch5vhtrbb",
				"\"access_token2\": \"xoxa-bykch5vhtrbb",
				"\"refresh_token1\": \"xoxr-6-sndbkwds64do",
				"\"refresh_token2\": \"xoxr-sndbkwds64do",
			},
			falsePositives: []string{
				// "xoxa-faketoken",
				// "xoxa-access-token-string",
				// "XOXa-nx991k",
				"https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SlackLegacyWorkspaceToken())
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
