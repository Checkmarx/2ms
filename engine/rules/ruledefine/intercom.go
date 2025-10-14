package ruledefine

var IntercomAPIKeyRegex = generateSemiGenericRegex([]string{"intercom"}, AlphaNumericExtended("60"), true)

func Intercom() *Rule {
	return &Rule{
		BaseRuleID:      "e278713e-4f19-4dda-a459-1512735b598c",
		Description:     "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:          "intercom-api-key",
		Regex:           IntercomAPIKeyRegex,
		Keywords:        []string{"intercom"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCustomerSupport, RuleType: 4},
	}
}
