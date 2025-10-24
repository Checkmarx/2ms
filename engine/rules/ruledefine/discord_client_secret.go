package ruledefine

var discordClientSecretRegex = generateSemiGenericRegex([]string{"discord"}, AlphaNumericExtended("32"), true).String()

func DiscordClientSecret() *Rule {
	return &Rule{
		RuleID:          "2f9d5abf-e0c1-4ee9-8224-1a6a4ee9979e",
		Description:     "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		RuleName:        "discord-client-secret",
		Regex:           discordClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"discord"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
