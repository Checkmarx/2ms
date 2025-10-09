package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DiscordClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"discord"}, utils.AlphaNumericExtended("32"), true)

func DiscordClientSecret() *Rule {
	return &Rule{
		BaseRuleID:      "2f9d5abf-e0c1-4ee9-8224-1a6a4ee9979e",
		Description:     "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		RuleID:          "discord-client-secret",
		Regex:           DiscordClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"discord"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
