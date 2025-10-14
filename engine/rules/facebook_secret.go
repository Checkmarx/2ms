package rules

var FacebookSecretRegex = generateSemiGenericRegex([]string{"facebook"}, Hex("32"), true)

func FacebookSecret() *Rule {
	return &Rule{
		BaseRuleID: "28ab7c53-4f4e-4ebc-b5c6-87f6cbb1b30e",
		Description: "Discovered a Facebook Application secret," +
			" posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:          "facebook-secret",
		Regex:           FacebookSecretRegex,
		Entropy:         3,
		Keywords:        []string{"facebook"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
