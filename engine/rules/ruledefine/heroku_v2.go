package ruledefine

var herokuAPIKeyV2Regex = generateUniqueTokenRegex(`(HRKU-AA[0-9a-zA-Z_-]{58})`, false).String()

func HerokuV2() *Rule {
	return &Rule{
		RuleID:          "fcbe029b-6784-4636-aad4-ea982f6e010b",
		Description:     "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleName:        "Heroku-Api-Key-V2",
		Regex:           herokuAPIKeyV2Regex,
		Entropy:         4,
		Keywords:        []string{"HRKU-AA"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
