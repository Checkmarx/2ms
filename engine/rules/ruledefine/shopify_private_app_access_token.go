package ruledefine

import (
	"regexp"
)

var shopifyPrivateAppAccessTokenRegex = regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`)

func ShopifyPrivateAppAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "f869ed25-7389-48d6-bb6f-736a2faef111",
		Description:     "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
		RuleID:          "shopify-private-app-access-token",
		Regex:           shopifyPrivateAppAccessTokenRegex,
		Entropy:         2,
		Keywords:        []string{"shppa_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
