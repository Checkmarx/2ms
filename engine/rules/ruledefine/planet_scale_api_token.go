package ruledefine

var planetScaleAPITokenRegex = generateUniqueTokenRegex(`pscale_tkn_(?i)[\w=\.-]{32,64}`, false).String()

func PlanetScaleAPIToken() *Rule {
	return &Rule{
		RuleID:      "466bd91b-59c9-46e8-8a70-2e51e679d34e",
		Description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
		RuleName:    "planetscale-api-token",
		Regex:       planetScaleAPITokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_tkn_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
