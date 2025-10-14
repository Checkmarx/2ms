package ruledefine

var AdobeClientSecretRegex = generateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false)

func AdobeClientSecret() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "4d0dc375-5c50-4c2d-9bb7-c57677c085c1",
		RuleID:     "adobe-client-secret",
		Description: "Discovered a potential Adobe Client Secret, which," +
			" if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:           AdobeClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"p8e-"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
