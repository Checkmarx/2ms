package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var RapidAPIAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"rapidapi"},
	utils.AlphaNumericExtendedShort("50"), true)

func RapidAPIAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "f4f4feea-e8d0-4c8d-ab8f-833e673a9ff8",
		Description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
		RuleID:      "rapidapi-access-token",
		Regex:       RapidAPIAccessTokenRegex,
		Keywords: []string{
			"rapidapi",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
