package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AsanaClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"asana"}, utils.AlphaNumeric("32"), true)

func AsanaClientSecret() *NewRule {
	return &NewRule{
		Description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
		RuleID:      "asana-client-secret",
		Regex:       AsanaClientSecretRegex,
		Keywords:    []string{"asana"},
	}
}
