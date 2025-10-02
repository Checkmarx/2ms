package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BitbucketClientIdRegex = utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumeric("32"), true)

func BitBucketClientID() *NewRule {
	return &NewRule{
		BaseRuleID:      "adc652bc-4f17-48b6-8f23-fd3aca2a31e3",
		Description:     "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:          "bitbucket-client-id",
		Regex:           BitbucketClientIdRegex,
		Keywords:        []string{"bitbucket"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 1},
	}
}
