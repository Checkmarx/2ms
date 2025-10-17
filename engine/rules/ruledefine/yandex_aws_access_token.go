package ruledefine

var yandexAWSAccessTokenRegex = generateSemiGenericRegex([]string{"yandex"},
	`YC[a-zA-Z0-9_\-]{38}`, true).String()

func YandexAWSAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "be6d21db-8a6d-4cfa-abfb-3047ed5b6ea8",
		Description: "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.",
		RuleID:      "yandex-aws-access-token",
		Regex:       yandexAWSAccessTokenRegex,
		Keywords: []string{
			"yandex",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
