package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BitbucketClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumericExtended("64"), true)

func BitBucketClientSecret() *NewRule {
	return &NewRule{
		BaseRuleID: "2772c249-2dd8-4cc4-8d52-ef264eb71802",
		Description: "Discovered a potential Bitbucket Client Secret," +
			" posing a risk of compromised code repositories and unauthorized access.",
		RuleID:          "bitbucket-client-secret",
		Regex:           BitbucketClientSecretRegex,
		Keywords:        []string{"bitbucket"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
