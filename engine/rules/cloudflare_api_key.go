package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var cloudfareIdentifiers = []string{"cloudflare"}

var CloudflareApiKeyRegex = utils.GenerateSemiGenericRegex(cloudfareIdentifiers, utils.AlphaNumericExtendedShort("40"), true)

func CloudflareAPIKey() *Rule {
	return &Rule{
		BaseRuleID:      "c0c2396e-e2c2-409b-befb-e7bdff313f56",
		Description:     "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:          "cloudflare-api-key",
		Regex:           CloudflareApiKeyRegex,
		Entropy:         2,
		Keywords:        cloudfareIdentifiers,
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
