package rules

var SnykRegex = generateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, Hex8_4_4_4_12(), true)

func Snyk() *Rule {
	return &Rule{
		BaseRuleID:      "152b3ca6-408d-4b3b-b5b9-1f74f00df88e",
		Description:     "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:          "snyk-api-token",
		Regex:           SnykRegex,
		Keywords:        []string{"snyk"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
	}
}
