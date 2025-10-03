package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SumoLogicAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true)

func SumoLogicAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "85b0efa8-7e80-41d9-b855-86720a35a39f",
		RuleID:      "sumologic-access-token",
		Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
