package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BitbucketClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumericExtended("64"), true)

func BitbucketClientSecret() *NewRule {
	return &NewRule{
		Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
		RuleID:      "bitbucket-client-secret",
		Regex:       BitbucketClientSecretRegex,
		Keywords:    []string{"bitbucket"},
	}
}
