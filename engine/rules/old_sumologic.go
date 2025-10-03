package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OldSumoLogicAccessID() *config.Rule {
	return &config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}
}

func OldSumoLogicAccessToken() *config.Rule {
	return &config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}
}
