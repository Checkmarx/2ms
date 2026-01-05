package ruledefine

var etsyAccessTokenRegex = generateSemiGenericRegex(
	[]string{"(?-i:ETSY|[Ee]tsy)"}, AlphaNumeric("24"), true).String()

func EtsyAccessToken() *Rule {
	return &Rule{
		RuleID:      "f7c07912-06d6-4fd5-ac9b-4547fcc0385a",
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		RuleName:    "Etsy-Access-Token",
		Regex:       etsyAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"etsy",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryECommercePlatform,
		ScoreRuleType: 4,
	}
}
