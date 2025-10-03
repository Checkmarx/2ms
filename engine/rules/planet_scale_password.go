package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var PlanetScalePasswordRegex = utils.GenerateUniqueTokenRegex(`pscale_pw_(?i)[\w=\.-]{32,64}`, true)

func PlanetScalePassword() *NewRule {
	return &NewRule{
		BaseRuleID:  "a8421e75-0e5d-45f6-93d8-67f09acc498c",
		Description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
		RuleID:      "planetscale-password",
		Regex:       PlanetScalePasswordRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_pw_",
		},
		Severity:        "High",
		Tags:            []string{TagPassword},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
