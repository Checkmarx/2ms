package ruledefine

var freshbooksAccessTokenRegex = generateSemiGenericRegex(
	[]string{"freshbooks"}, AlphaNumeric("64"), true).String()

func FreshbooksAccessToken() *Rule {
	return &Rule{
		RuleID:      "59125af0-344b-4978-9f8f-99cc95a250c9",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		RuleName:    "Freshbooks-Access-Token",
		Regex:       freshbooksAccessTokenRegex,
		Keywords: []string{
			"freshbooks",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
