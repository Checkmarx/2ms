package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ConfluentSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("64"), true)

func ConfluentSecretKey() *NewRule {
	return &NewRule{
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		RuleID:      "confluent-secret-key",
		Regex:       ConfluentSecretKeyRegex,

		Keywords: []string{
			"confluent",
		},
	}
}
