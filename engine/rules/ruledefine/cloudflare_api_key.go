package ruledefine

var cloudfareIdentifiers = []string{"cloudflare"}

var cloudflareApiKeyRegex = generateSemiGenericRegex(cloudfareIdentifiers, AlphaNumericExtendedShort("40"), true)

func CloudflareAPIKey() *Rule {
	return &Rule{
		RuleID:          "c0c2396e-e2c2-409b-befb-e7bdff313f56",
		Description:     "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.",
		RuleName:        "cloudflare-api-key",
		Regex:           cloudflareApiKeyRegex.String(),
		Entropy:         2,
		Keywords:        cloudfareIdentifiers,
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
