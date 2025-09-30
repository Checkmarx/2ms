package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DatadogAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"datadog"},
	utils.AlphaNumeric("40"), true)

func DatadogAccessToken() *NewRule {
	return &NewRule{
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		RuleID:      "datadog-access-token",
		Regex:       DatadogAccessTokenRegex,

		Keywords: []string{
			"datadog",
		},
	}
}
