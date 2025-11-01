package ruledefine

var contentfulDeliveryApiTokenRegex = generateSemiGenericRegex([]string{"contentful"},
	AlphaNumericExtended("43"), true)

func Contentful() *Rule {
	return &Rule{
		RuleID:          "57bc117a-aa30-4c28-a357-952c85938db8",
		Description:     "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleName:        "Contentful-Delivery-Api-Token",
		Regex:           contentfulDeliveryApiTokenRegex.String(),
		Keywords:        []string{"contentful"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryContentManagementSystem, RuleType: 4},
	}
}
