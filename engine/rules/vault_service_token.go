package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var VaultServiceTokenRegex = utils.GenerateUniqueTokenRegex(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`, false)

func VaultServiceToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "1cfd6d4a-273d-47f6-92ac-ee8f8f472f66",
		RuleID:      "vault-service-token",
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		Regex:       VaultServiceTokenRegex,
		Entropy:     3.5,
		Keywords:    []string{"hvs.", "s."},
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					// https://github.com/gitleaks/gitleaks/issues/1490#issuecomment-2334166357
					regexp.MustCompile(`s\.[A-Za-z]{24}`),
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
