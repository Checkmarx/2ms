package ruledefine

import (
	"regexp"
)

var slackLegacyTokenRegex = regexp.MustCompile(`xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`).String()

func SlackLegacyToken() *Rule {
	return &Rule{
		BaseRuleID:      "36fda798-a1f0-40cb-b836-400c3b11e219",
		RuleID:          "slack-legacy-token",
		Description:     "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.",
		Regex:           slackLegacyTokenRegex,
		Entropy:         2,
		Keywords:        []string{"xoxo", "xoxs"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
