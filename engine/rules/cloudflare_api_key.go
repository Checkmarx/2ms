package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var cloudfare_global_keys = []string{
	`cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`, // gitleaks:allow
	`CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c`,    // gitleaks:allow
	`cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`,                 // gitleaks:allow
}

var cloudfare_api_keys = []string{
	`cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, // gitleaks:allow
	`CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc`,    // gitleaks:allow
	`cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`,          // gitleaks:allow
}

var cloudfare_origin_ca_keys = []string{
	`CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5`,
	`CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed`,
}

var cloudfareIdentifiers = []string{"cloudflare"}

var CloudflareApiKeyRegex = utils.GenerateSemiGenericRegex(cloudfareIdentifiers, utils.AlphaNumericExtendedShort("40"), true)

func CloudflareApiKey() *NewRule {
	return &NewRule{
		Description: "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "cloudflare-api-key",
		Regex:       CloudflareApiKeyRegex,
		Entropy:     2,
		Keywords:    cloudfareIdentifiers,
	}
}
