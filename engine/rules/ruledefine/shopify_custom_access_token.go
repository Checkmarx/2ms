package ruledefine

import (
	"regexp"
)

var ShopifyCustomAccessTokenRegex = regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`)

func ShopifyCustomAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "f98c5ec1-dd8d-42d4-b07d-9737ae65eec1",
		Description:     "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
		RuleID:          "shopify-custom-access-token",
		Regex:           ShopifyCustomAccessTokenRegex,
		Entropy:         2,
		Keywords:        []string{"shpca_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
