package ruledefine

var twitchAPITokenRegex = generateSemiGenericRegex([]string{"twitch"}, AlphaNumeric("30"), true).String()

func TwitchAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "2361985f-3d77-4151-ad00-6d7a2ecbb700",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		RuleID:      "twitch-api-token",
		Regex:       twitchAPITokenRegex,
		Keywords: []string{
			"twitch",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
