package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var VaultBatchTokenRegex = utils.GenerateUniqueTokenRegex(`hvb\.[\w-]{138,300}`, false)

func VaultBatchToken() *Rule {
	return &Rule{
		BaseRuleID:      "32031c1f-7fbc-4047-a2a3-cd618e4b1c0a",
		Description:     "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
		RuleID:          "vault-batch-token",
		Regex:           VaultBatchTokenRegex,
		Entropy:         4,
		Keywords:        []string{"hvb."},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
	}
}
