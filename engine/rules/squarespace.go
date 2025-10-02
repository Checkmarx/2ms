package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SquareSpaceAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"squarespace"}, utils.Hex8_4_4_4_12(), true)

func SquareSpaceAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "775c744f-1469-4ac2-bdbf-8480ae246451",
		Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
		RuleID:      "squarespace-access-token",
		Regex:       SquareSpaceAccessTokenRegex,
		Keywords: []string{
			"squarespace",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
