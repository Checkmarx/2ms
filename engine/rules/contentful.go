package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ContentfulDeliveryApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"contentful"},
	utils.AlphaNumericExtended("43"), true)

func Contentful() *NewRule {
	return &NewRule{
		BaseRuleID:      "57bc117a-aa30-4c28-a357-952c85938db8",
		Description:     "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleID:          "contentful-delivery-api-token",
		Regex:           ContentfulDeliveryApiTokenRegex,
		Keywords:        []string{"contentful"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryContentManagementSystem, RuleType: 4},
	}
}
