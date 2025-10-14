package rules

import (
	"regexp"
)

var ShopifySharedSecretRegex = regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`)

func ShopifySharedSecret() *Rule {
	return &Rule{
		BaseRuleID:      "a94e9d58-07d6-427f-b95c-f6a44ae9b914",
		Description:     "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
		RuleID:          "shopify-shared-secret",
		Regex:           ShopifySharedSecretRegex,
		Entropy:         2,
		Keywords:        []string{"shpss_"},
		Severity:        "High",
		Tags:            []string{TagPublicSecret},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
