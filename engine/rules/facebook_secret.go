package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FacebookSecretRegex = utils.GenerateSemiGenericRegex([]string{"facebook"}, utils.Hex("32"), true)

func FacebookSecret() *NewRule {
	return &NewRule{
		Description: "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook-secret",
		Regex:       FacebookSecretRegex,
		Entropy:     3,
		Keywords:    []string{"facebook"},
	}
}
