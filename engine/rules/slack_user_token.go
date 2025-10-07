package rules

import (
	"regexp"
)

var SlackUserTokenRegex = regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`) //nolint:gocritic

func SlackUserToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "c855c7d9-6b81-46c2-977f-e01e73bc860b",
		RuleID:      "slack-user-token",
		Description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
		// The last segment seems to be consistently 32 characters. I've made it 28-34 just in case.
		Regex:           SlackUserTokenRegex,
		Entropy:         2,
		Keywords:        []string{"xoxp-", "xoxe-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
