package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FreshbooksAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"freshbooks"}, utils.AlphaNumeric("64"), true)

func FreshbooksAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "59125af0-344b-4978-9f8f-99cc95a250c9",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		RuleID:      "freshbooks-access-token",
		Regex:       FreshbooksAccessTokenRegex,
		Keywords: []string{
			"freshbooks",
		},
		Severity: "High",
	}
}
