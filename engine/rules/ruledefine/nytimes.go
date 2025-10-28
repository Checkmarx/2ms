package ruledefine

var nytimesAccessTokenRegex = generateSemiGenericRegex([]string{
	"nytimes", "new-york-times,", "newyorktimes"},
	AlphaNumericExtended("32"), true).String()

func NytimesAccessToken() *Rule {
	return &Rule{
		RuleID:      "0ee134ac-689a-490a-bcd7-f773e535dfda",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		RuleName:    "nytimes-access-token",
		Regex:       nytimesAccessTokenRegex,
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
