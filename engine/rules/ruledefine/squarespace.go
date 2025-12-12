package ruledefine

var squareSpaceAccessTokenRegex = generateSemiGenericRegex([]string{"squarespace"}, Hex8_4_4_4_12(), true).String()

func SquareSpaceAccessToken() *Rule {
	return &Rule{
		RuleID:      "775c744f-1469-4ac2-bdbf-8480ae246451",
		Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
		RuleName:    "Squarespace-Access-Token",
		Regex:       squareSpaceAccessTokenRegex,
		Keywords: []string{
			"squarespace",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryWebHostingAndDeployment,
		ScoreRuleType: 4,
	}
}
