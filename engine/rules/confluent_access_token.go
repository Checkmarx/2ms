package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ConfluentAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("16"), true)

func ConfluentAccessToken() *NewRule {
	return &NewRule{
		Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
		RuleID:      "confluent-access-token",
		Regex:       ConfluentAccessTokenRegex,

		Keywords: []string{
			"confluent",
		},
	}
}
