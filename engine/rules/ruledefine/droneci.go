package ruledefine

var droneciAccessTokenRegex = generateSemiGenericRegex([]string{"droneci"}, AlphaNumeric("32"), true).String()

func DroneciAccessToken() *Rule {
	return &Rule{
		RuleID:      "3f1cd49c-40d5-460d-95b3-df97293ecf3f",
		Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
		RuleName:    "Droneci-Access-Token",
		Regex:       droneciAccessTokenRegex,
		Keywords: []string{
			"droneci",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
