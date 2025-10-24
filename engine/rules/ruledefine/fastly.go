package ruledefine

var fastlyAPITokenRegex = generateSemiGenericRegex(
	[]string{"fastly"}, AlphaNumericExtended("32"), true).String()

func FastlyAPIToken() *Rule {
	return &Rule{
		RuleID: "698e8f80-f409-4a03-99d1-cf4891ce7479",
		Description: "Uncovered a Fastly API key," +
			" which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleName:        "fastly-api-token",
		Regex:           fastlyAPITokenRegex,
		Keywords:        []string{"fastly"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
