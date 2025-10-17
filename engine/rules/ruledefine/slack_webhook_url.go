package ruledefine

import (
	"regexp"
)

var slackWebHookUrlRegex = regexp.MustCompile(
	`(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`).String() //nolint:gocritic

func SlackWebHookUrl() *Rule {
	return &Rule{
		BaseRuleID:  "2c13ac3b-6279-4535-bd88-c23f938f2408",
		RuleID:      "slack-webhook-url",
		Description: "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.",
		// If this generates too many false-positives we should define an allowlist (e.g., "xxxx", "00000").
		Regex: slackWebHookUrlRegex,
		Keywords: []string{
			"hooks.slack.com",
		},
		Severity:        "High",
		Tags:            []string{TagWebhook},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
