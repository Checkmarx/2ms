package ruledefine

import (
	"regexp"
)

var shopifySharedSecretRegex = regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`).String()

func ShopifySharedSecret() *Rule {
	return &Rule{
		RuleID:          "a94e9d58-07d6-427f-b95c-f6a44ae9b914",
		Description:     "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
		RuleName:        "shopify-shared-secret",
		Regex:           shopifySharedSecretRegex,
		Entropy:         2,
		Keywords:        []string{"shpss_"},
		Severity:        "High",
		Tags:            []string{TagPublicSecret},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
