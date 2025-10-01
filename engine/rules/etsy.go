package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var EtsyAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"(?-i:ETSY|[Ee]tsy)"}, utils.AlphaNumeric("24"), true)

func EtsyAccessToken() *NewRule {
	return &NewRule{
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		RuleID:      "etsy-access-token",
		Regex:       EtsyAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"etsy",
		},
	}
}
