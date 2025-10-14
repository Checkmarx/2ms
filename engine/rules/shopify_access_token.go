package rules

import (
	"regexp"
)

var ShopifyAccessTokenRegex = regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`)

func ShopifyAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "d80661bb-1980-4686-8666-3b87e66ae863",
		Description:     "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
		RuleID:          "shopify-access-token",
		Regex:           ShopifyAccessTokenRegex,
		Entropy:         2,
		Keywords:        []string{"shpat_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
