package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DroneciAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"droneci"}, utils.AlphaNumeric("32"), true)

func DroneciAccessToken() *NewRule {
	return &NewRule{
		Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
		RuleID:      "droneci-access-token",
		Regex:       DroneciAccessTokenRegex,
		Keywords: []string{
			"droneci",
		},
	}
}
