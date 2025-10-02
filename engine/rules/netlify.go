package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NetlifyAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"netlify"},
	utils.AlphaNumericExtended("40,46"), true)

func NetlifyAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "c23decf4-9f16-4ec6-8481-b3423f12ed4c",
		Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
		RuleID:      "netlify-access-token",
		Regex:       NetlifyAccessTokenRegex,
		Keywords: []string{
			"netlify",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
