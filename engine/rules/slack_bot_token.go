package rules

import (
	"regexp"
)

var SlackBotTokenRegex = regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`) //nolint:gocritic

func SlackBotToken() *Rule {
	return &Rule{
		BaseRuleID:  "5d9126ea-e73c-4a6e-bfc7-08fb675f1937",
		RuleID:      "slack-bot-token",
		Description: "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
		Regex:       SlackBotTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"xoxb",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
