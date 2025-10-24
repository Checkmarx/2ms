package ruledefine

var cloudflareGlobalApiKeyRegex = generateSemiGenericRegex(cloudfareIdentifiers, Hex("37"), true)

func CloudflareGlobalAPIKey() *Rule {
	return &Rule{
		RuleID:          "b29bf06c-28c1-4251-8820-ae1110c58709",
		Description:     "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
		RuleName:        "cloudflare-global-api-key",
		Regex:           cloudflareGlobalApiKeyRegex.String(),
		Entropy:         2,
		Keywords:        cloudfareIdentifiers,
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
