package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DroneciAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"droneci"}, utils.AlphaNumeric("32"), true)

func DroneciAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "3f1cd49c-40d5-460d-95b3-df97293ecf3f",
		Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
		RuleID:      "droneci-access-token",
		Regex:       DroneciAccessTokenRegex,
		Keywords: []string{
			"droneci",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
