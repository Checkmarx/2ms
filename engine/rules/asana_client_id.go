package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AsanaClientIdRegex = utils.GenerateSemiGenericRegex([]string{"asana"}, utils.Numeric("16"), true)

func AsanaClientId() *NewRule {
	return &NewRule{
		Description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
		RuleID:      "asana-client-id",
		Regex:       AsanaClientIdRegex,
		Keywords:    []string{"asana"},
	}
}
