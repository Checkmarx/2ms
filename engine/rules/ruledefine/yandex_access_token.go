package ruledefine

var yandexAccessTokenRegex = generateSemiGenericRegex([]string{"yandex"},
	`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`, true).String()

func YandexAccessToken() *Rule {
	return &Rule{
		RuleID:      "b1bba54f-7da9-49a4-b057-e05dac03835a",
		Description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
		RuleName:    "Yandex-Access-Token",
		Regex:       yandexAccessTokenRegex,
		Keywords: []string{
			"yandex",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryCloudPlatform,
		ScoreRuleType: 4,
	}
}
