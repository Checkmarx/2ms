package ruledefine

var squareSpaceAccessTokenRegex = generateSemiGenericRegex([]string{"squarespace"}, Hex8_4_4_4_12(), true).String()

func SquareSpaceAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "775c744f-1469-4ac2-bdbf-8480ae246451",
		Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
		RuleID:      "squarespace-access-token",
		Regex:       squareSpaceAccessTokenRegex,
		Keywords: []string{
			"squarespace",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
