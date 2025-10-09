package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var AzureActiveDirectoryClientSecretRegex = regexp.MustCompile(`(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`) //nolint:lll

func AzureActiveDirectoryClientSecret() *Rule {
	return &Rule{
		BaseRuleID:  "459f11f0-f5b3-497e-bd6b-ad36a0db5f2d",
		RuleID:      "azure-ad-client-secret",
		Description: "Azure AD Client Secret",
		// After inspecting dozens of secrets, I'm fairly confident that they start with `xxx\dQ~`.
		// However, this may not be (entirely) true, and this rule might need to be further refined in the future.
		// Furthermore, it's possible that secrets have a checksum that could be used to further constrain this pattern.
		Regex:   AzureActiveDirectoryClientSecretRegex,
		Entropy: 3,
		Keywords: []string{
			"Q~",
		},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
