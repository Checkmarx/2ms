package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FacebookPageAccessTokenRegex = utils.GenerateUniqueTokenRegex("EAA[MC](?i)[a-z0-9]{100,}", false)

func FacebookPageAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "aa0c13ec-cd3f-43a1-806f-05006e342946",
		Description:     "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:          "facebook-page-access-token",
		Regex:           FacebookPageAccessTokenRegex,
		Entropy:         4,
		Keywords:        []string{"EAAM", "EAAC"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
