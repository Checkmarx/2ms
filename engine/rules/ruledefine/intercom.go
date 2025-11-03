package ruledefine

var intercomAPIKeyRegex = generateSemiGenericRegex([]string{"intercom"}, AlphaNumericExtended("60"), true).String()

func Intercom() *Rule {
	return &Rule{
		RuleID:          "e278713e-4f19-4dda-a459-1512735b598c",
		Description:     "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleName:        "Intercom-Api-Key",
		Regex:           intercomAPIKeyRegex,
		Keywords:        []string{"intercom"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCustomerSupport, RuleType: 4},
	}
}
