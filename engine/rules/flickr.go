package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FlickrAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"flickr"}, utils.AlphaNumeric("32"), true)

func FlickrAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "6ee4f7a1-196f-47ad-b0e9-015dfeb0258f",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		RuleID:      "flickr-access-token",
		Regex:       FlickrAccessTokenRegex,
		Keywords: []string{
			"flickr",
		},
		Severity: "High",
	}
}
