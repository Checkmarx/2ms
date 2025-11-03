package ruledefine

var adobeClientSecretRegex = generateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false).String()

func AdobeClientSecret() *Rule {
	// define rule
	return &Rule{
		RuleID:   "4d0dc375-5c50-4c2d-9bb7-c57677c085c1",
		RuleName: "Adobe-Client-Secret",
		Description: "Discovered a potential Adobe Client Secret, which," +
			" if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:           adobeClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"p8e-"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
