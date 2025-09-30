package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CodecovAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"codecov"}, utils.AlphaNumeric("32"), true)

func CodecovAccessToken() *NewRule {
	return &NewRule{
		Description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
		RuleID:      "codecov-access-token",
		Regex:       CodecovAccessTokenRegex,
		Keywords: []string{
			"codecov",
		},
	}
}
