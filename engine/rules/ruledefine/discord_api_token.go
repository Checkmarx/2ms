package ruledefine

var discordApiTokenRegex = generateSemiGenericRegex([]string{"discord"}, Hex("64"), true).String()

func DiscordAPIToken() *Rule {
	return &Rule{
		RuleID:          "f12c782e-bfea-4e23-ba78-0cf033558387",
		Description:     "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		RuleName:        "discord-api-token",
		Regex:           discordApiTokenRegex,
		Keywords:        []string{"discord"},
		Severity:        "High",
		Tags:            []string{TagApiKey, TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
