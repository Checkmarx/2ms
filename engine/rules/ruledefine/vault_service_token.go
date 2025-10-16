package ruledefine

import (
	"regexp"
)

var vaultServiceTokenRegex = generateUniqueTokenRegex(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`, false)

func VaultServiceToken() *Rule {
	return &Rule{
		BaseRuleID:  "1cfd6d4a-273d-47f6-92ac-ee8f8f472f66",
		RuleID:      "vault-service-token",
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		Regex:       vaultServiceTokenRegex,
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
