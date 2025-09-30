package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CloudflareGlobalApiKeyRegex = utils.GenerateSemiGenericRegex(cloudfareIdentifiers, utils.Hex("37"), true)

func CloudflareGlobalApiKey() *NewRule {
	return &NewRule{
		Description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "cloudflare-global-api-key",
		Regex:       CloudflareGlobalApiKeyRegex,
		Entropy:     2,
		Keywords:    cloudfareIdentifiers,
	}
}
