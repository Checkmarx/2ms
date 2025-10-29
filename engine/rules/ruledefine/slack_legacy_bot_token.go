package ruledefine

import (
	"regexp"
)

var slackLegacyBotTokenRegex = regexp.MustCompile(`xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`).String() //nolint:gocritic

func SlackLegacyBotToken() *Rule {
	return &Rule{
		RuleID:      "e0a8f972-ad70-4dba-85e3-4f19bd447800",
		RuleName:    "Slack-Legacy-Bot-Token",
		Description: "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.",
		// This rule is based off the limited information I could find and may not be 100% accurate.
		Regex:   slackLegacyBotTokenRegex,
		Entropy: 2,
		Keywords: []string{
			"xoxb",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
