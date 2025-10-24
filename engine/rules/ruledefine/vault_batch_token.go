package ruledefine

var vaultBatchTokenRegex = generateUniqueTokenRegex(`hvb\.[\w-]{138,300}`, false).String()

func VaultBatchToken() *Rule {
	return &Rule{
		RuleID:          "32031c1f-7fbc-4047-a2a3-cd618e4b1c0a",
		Description:     "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
		RuleName:        "vault-batch-token",
		Regex:           vaultBatchTokenRegex,
		Entropy:         4,
		Keywords:        []string{"hvb."},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
	}
}
