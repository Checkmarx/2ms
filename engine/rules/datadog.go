package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DatadogAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"datadog"},
	utils.AlphaNumeric("40"), true)

func DatadogtokenAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "f0967e3a-826e-4abd-9271-bc7db50d168d",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		RuleID:      "datadog-access-token",
		Regex:       DatadogAccessTokenRegex,

		Keywords: []string{
			"datadog",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken, TagClientId},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
