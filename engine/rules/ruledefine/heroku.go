package ruledefine

var herokuAPIKeyRegex = generateSemiGenericRegex([]string{"heroku"}, Hex8_4_4_4_12(), true).String()

func Heroku() *Rule {
	return &Rule{
		BaseRuleID:      "4590b0c1-a67f-4fd5-b949-51e844cff884",
		Description:     "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:          "heroku-api-key",
		Regex:           herokuAPIKeyRegex,
		Keywords:        []string{"heroku"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
