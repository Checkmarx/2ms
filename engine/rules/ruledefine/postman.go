package ruledefine

var postManAPIRegex = generateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`, false).String()

func PostManAPI() *Rule {
	return &Rule{
		RuleID:      "bae405c3-705b-420b-bdc4-ed3613add3da",
		Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
		RuleName:    "Postman-Api-Token",
		Regex:       postManAPIRegex,
		Entropy:     3,
		Keywords: []string{
			"PMAK-",
		},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryAPIAccess,
		ScoreRuleType: 4,
	}
}
