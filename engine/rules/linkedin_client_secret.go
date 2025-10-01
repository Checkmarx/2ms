package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var LinkedinClientSecretRegex = utils.GenerateSemiGenericRegex([]string{
	"linked[_-]?in",
}, utils.AlphaNumeric("16"), true)

func LinkedinClientSecret() *NewRule {
	return &NewRule{
		BaseRuleID:  "266e5b15-aa39-4e8f-b7f4-6ce98a624d6a",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		RuleID:      "linkedin-client-secret",
		Regex:       LinkedinClientSecretRegex,
		Entropy:     2,
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Severity: "High",
	}
}
