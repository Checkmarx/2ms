package ruledefine

var snykRegex = generateSemiGenericRegex(
	[]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, Hex8_4_4_4_12(), true).String()

func Snyk() *Rule {
	return &Rule{
		RuleID:        "152b3ca6-408d-4b3b-b5b9-1f74f00df88e",
		Description:   "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleName:      "Snyk-Api-Token",
		Regex:         snykRegex,
		Keywords:      []string{"snyk"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategorySecurity,
		ScoreRuleType: 4,
	}
}
