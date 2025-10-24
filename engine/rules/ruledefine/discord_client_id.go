package ruledefine

var discordClientIdRegex = generateSemiGenericRegex([]string{"discord"}, Numeric("18"), true).String()

func DiscordClientID() *Rule {
	return &Rule{
		RuleID:          "5c0a6af7-9fa7-4d15-b25c-8884197fc9da",
		Description:     "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		RuleName:        "discord-client-id",
		Regex:           discordClientIdRegex,
		Entropy:         2,
		Keywords:        []string{"discord"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
	}
}
