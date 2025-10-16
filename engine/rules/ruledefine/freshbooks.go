package ruledefine

var freshbooksAccessTokenRegex = generateSemiGenericRegex([]string{"freshbooks"}, AlphaNumeric("64"), true)

func FreshbooksAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "59125af0-344b-4978-9f8f-99cc95a250c9",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		RuleID:      "freshbooks-access-token",
		Regex:       freshbooksAccessTokenRegex,
		Keywords: []string{
			"freshbooks",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
