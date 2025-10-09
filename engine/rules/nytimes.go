package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NytimesAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{
	"nytimes", "new-york-times,", "newyorktimes"},
	utils.AlphaNumericExtended("32"), true)

func NytimesAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "0ee134ac-689a-490a-bcd7-f773e535dfda",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		RuleID:      "nytimes-access-token",
		Regex:       NytimesAccessTokenRegex,
		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
