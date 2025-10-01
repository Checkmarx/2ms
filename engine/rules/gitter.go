package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var GitterAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"gitter"},
	utils.AlphaNumericExtendedShort("40"), true)

func GitterAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "3b70b51e-5d70-485b-bf23-6b96cbda7133",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		RuleID:      "gitter-access-token",
		Regex:       GitterAccessTokenRegex,
		Keywords: []string{
			"gitter",
		},
		Severity: "High",
	}
}
