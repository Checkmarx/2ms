package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var JwtRegex = utils.GenerateUniqueTokenRegex(`ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?`, false)

func JWT() *NewRule {
	return &NewRule{
		BaseRuleID:  "37dfe666-1961-48f8-b618-fa6321c216d1",
		Description: "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
		RuleID:      "jwt",
		Regex:       JwtRegex,
		Entropy:     3,
		Keywords:    []string{"ey"},
		Severity:    "High",
	}
}
