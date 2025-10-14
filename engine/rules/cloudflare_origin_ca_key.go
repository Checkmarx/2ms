package rules

var CloudflareOriginCaKeyRegex = generateUniqueTokenRegex(`v1\.0-`+Hex("24")+"-"+Hex("146"), false)
var caIdentifiers = append(cloudfareIdentifiers, "v1.0-")

func CloudflareOriginCAKey() *Rule {
	return &Rule{
		BaseRuleID:      "0fac5c07-026b-45c8-9add-bc1357833d6e",
		Description:     "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
		RuleID:          "cloudflare-origin-ca-key",
		Regex:           CloudflareOriginCaKeyRegex,
		Entropy:         2,
		Keywords:        caIdentifiers,
		Severity:        "High",
		Tags:            []string{TagEncryptionKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
