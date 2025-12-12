package ruledefine

import (
	"regexp"
)

var shopifyCustomAccessTokenRegex = regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`).String()

func ShopifyCustomAccessToken() *Rule {
	return &Rule{
		RuleID:        "f98c5ec1-dd8d-42d4-b07d-9737ae65eec1",
		Description:   "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
		RuleName:      "Shopify-Custom-Access-Token",
		Regex:         shopifyCustomAccessTokenRegex,
		Entropy:       2,
		Keywords:      []string{"shpca_"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryECommercePlatform,
		ScoreRuleType: 4,
	}
}
