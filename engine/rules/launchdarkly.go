package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var LaunchdarklyAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"launchdarkly"}, utils.AlphaNumericExtended("40"), true)

func LaunchDarklyAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "f39021e6-f765-4d39-8fc5-2d6113b89a09",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		RuleID:      "launchdarkly-access-token",
		Regex:       LaunchdarklyAccessTokenRegex,
		Keywords: []string{
			"launchdarkly",
		},
		Severity: "High",
	}
}
