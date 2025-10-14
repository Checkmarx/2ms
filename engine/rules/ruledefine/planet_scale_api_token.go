package ruledefine

var PlanetScaleAPITokenRegex = generateUniqueTokenRegex(`pscale_tkn_(?i)[\w=\.-]{32,64}`, false)

func PlanetScaleAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "466bd91b-59c9-46e8-8a70-2e51e679d34e",
		Description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
		RuleID:      "planetscale-api-token",
		Regex:       PlanetScaleAPITokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_tkn_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
