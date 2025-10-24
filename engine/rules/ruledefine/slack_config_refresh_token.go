package ruledefine

import (
	"regexp"
)

var slackConfigurationRefreshTokenRegex = regexp.MustCompile(`(?i)xoxe-\d-[A-Z0-9]{146}`).String()

func SlackConfigurationRefreshToken() *Rule {
	return &Rule{
		RuleID:   "ca3e4937-076c-42bb-847b-bf558a3f36b3",
		RuleName: "slack-config-refresh-token",
		Description: "Discovered a Slack Configuration refresh token," +
			" potentially allowing prolonged unauthorized access to configuration settings.",
		Regex:           slackConfigurationRefreshTokenRegex,
		Entropy:         2,
		Keywords:        []string{"xoxe-"},
		Severity:        "High",
		Tags:            []string{TagRefreshToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
