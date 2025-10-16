package ruledefine

var etsyAccessTokenRegex = generateSemiGenericRegex([]string{"(?-i:ETSY|[Ee]tsy)"}, AlphaNumeric("24"), true)

func EtsyAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "f7c07912-06d6-4fd5-ac9b-4547fcc0385a",
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		RuleID:      "etsy-access-token",
		Regex:       etsyAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"etsy",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
