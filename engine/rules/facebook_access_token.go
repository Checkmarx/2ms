package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FacebookAccessTokenRegex = utils.GenerateUniqueTokenRegex(`\d{15,16}(\||%)[0-9a-z\-_]{27,40}`, true)

func FacebookAccessToken() *NewRule {
	return &NewRule{
		Description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook-access-token",
		Regex:       FacebookAccessTokenRegex,
		Entropy:     3,
		Keywords:    []string{"facebook"},
	}
}
