package ruledefine

var yandexAPIKeyRegex = generateSemiGenericRegex([]string{"yandex"},
	`AQVN[A-Za-z0-9_\-]{35,38}`, true).String()

func YandexAPIKey() *Rule {
	return &Rule{
		RuleID:      "62cf5f43-caaa-464b-a7a1-2fc9d16fd4d1",
		Description: "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.",
		RuleName:    "yandex-api-key",
		Regex:       yandexAPIKeyRegex,
		Keywords: []string{
			"yandex",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
