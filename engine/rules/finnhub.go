package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FinnhubAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"finnhub"}, utils.AlphaNumeric("20"), true)

func FinnhubAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "c91b2611-9756-4f63-b820-a236ece07b6b",
		Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
		RuleID:      "finnhub-access-token",
		Regex:       FinnhubAccessTokenRegex,
		Keywords: []string{
			"finnhub",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
