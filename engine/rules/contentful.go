package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ContentfulDeliveryApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"contentful"},
	utils.AlphaNumericExtended("43"), true)

func ContentfulDeliveryApiToken() *NewRule {
	return &NewRule{
		Description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleID:      "contentful-delivery-api-token",
		Regex:       ContentfulDeliveryApiTokenRegex,

		Keywords: []string{"contentful"},
	}
}
