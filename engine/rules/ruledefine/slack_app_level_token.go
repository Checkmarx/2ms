package ruledefine

import (
	"regexp"
)

var slackAppLevelTokenRegex = regexp.MustCompile(`(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`)

func SlackAppLevelToken() *Rule {
	return &Rule{
		BaseRuleID:  "dba4da5d-3e56-43d9-a130-ac4af070a7c8",
		RuleID:      "slack-app-token",
		Description: "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.",
		// This regex is based on a limited number of examples and may not be 100% accurate.
		Regex:           slackAppLevelTokenRegex,
		Entropy:         2,
		Keywords:        []string{"xapp"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
