package ruledefine

import (
	"regexp"
)

var slackConfigurationTokenRegex = regexp.MustCompile(`(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`).String()

func SlackConfigurationToken() *Rule {
	return &Rule{
		RuleID:        "82732b41-898d-4bf0-b5ec-224236bc2a79",
		RuleName:      "Slack-Config-Access-Token",
		Description:   "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.",
		Regex:         slackConfigurationTokenRegex,
		Entropy:       2,
		Keywords:      []string{"xoxe.xoxb-", "xoxe.xoxp-"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
