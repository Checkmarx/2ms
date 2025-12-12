package ruledefine

var planetScalePasswordRegex = generateUniqueTokenRegex(`pscale_pw_(?i)[\w=\.-]{32,64}`, true).String()

func PlanetScalePassword() *Rule {
	return &Rule{
		RuleID:      "a8421e75-0e5d-45f6-93d8-67f09acc498c",
		Description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
		RuleName:    "Planetscale-Password",
		Regex:       planetScalePasswordRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_pw_",
		},
		Severity:      "High",
		Tags:          []string{TagPassword},
		Category:      CategoryDatabaseAsAService,
		ScoreRuleType: 4,
	}
}
