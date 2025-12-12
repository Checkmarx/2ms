package ruledefine

import (
	"regexp"
)

var slackUserTokenRegex = regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`).String() //nolint:gocritic

func SlackUserToken() *Rule {
	return &Rule{
		RuleID:      "c855c7d9-6b81-46c2-977f-e01e73bc860b",
		RuleName:    "Slack-User-Token",
		Description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
		// The last segment seems to be consistently 32 characters. I've made it 28-34 just in case.
		Regex:         slackUserTokenRegex,
		Entropy:       2,
		Keywords:      []string{"xoxp-", "xoxe-"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
