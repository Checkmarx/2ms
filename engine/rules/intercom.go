package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var IntercomAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"intercom"}, utils.AlphaNumericExtended("60"), true)

func IntercomAPIKey() *NewRule {
	return &NewRule{
		BaseRuleID:  "e278713e-4f19-4dda-a459-1512735b598c",
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Regex:       IntercomAPIKeyRegex,
		Keywords:    []string{"intercom"},
		Severity:    "High",
	}
}
