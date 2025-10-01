package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FinicityClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"finicity"}, utils.AlphaNumeric("20"), true)

func FinicityClientSecret() *NewRule {
	return &NewRule{
		BaseRuleID:  "bc48d7fc-9dca-42f9-aefe-6d38b13f28c1",
		Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleID:      "finicity-client-secret",
		Regex:       FinicityClientSecretRegex,
		Keywords:    []string{"finicity"},
		Severity:    "High",
	}
}
