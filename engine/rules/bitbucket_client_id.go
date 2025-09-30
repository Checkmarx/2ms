package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BitbucketClientIdRegex = utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumeric("32"), true)

func BitbucketClientId() *NewRule {
	return &NewRule{
		Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:      "bitbucket-client-id",
		Regex:       BitbucketClientIdRegex,
		Keywords:    []string{"bitbucket"},
	}
}
