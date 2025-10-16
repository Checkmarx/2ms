package ruledefine

import (
	"regexp"
)

var teamsWebhookRegex = regexp.MustCompile(
	`https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`) //nolint:lll

func TeamsWebhook() *Rule {
	return &Rule{
		BaseRuleID:  "3dd9b1e8-00cf-4049-a5f8-f29fce0d742c",
		Description: "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.",
		RuleID:      "microsoft-teams-webhook",
		Regex:       teamsWebhookRegex,
		Keywords: []string{
			"webhook.office.com",
			"webhookb2",
			"IncomingWebhook",
		},
		Severity:        "High",
		Tags:            []string{TagWebhook},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
