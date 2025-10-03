package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CloudflareOriginCaKeyRegex = utils.GenerateUniqueTokenRegex(`v1\.0-`+utils.Hex("24")+"-"+utils.Hex("146"), false)
var caIdentifiers = append(cloudfareIdentifiers, "v1.0-")

func CloudflareOriginCAKey() *NewRule {
	return &NewRule{
		BaseRuleID:      "0f1e7b5c-5411-4bc7-98b2-743ef790186a",
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
