package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var KucoinAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex("24"), true)

func KucoinAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "64f3a17f-4d12-4527-b176-9b01fdffb496",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		RuleID:      "kucoin-access-token",
		Regex:       KucoinAccessTokenRegex,
		Keywords: []string{
			"kucoin",
		},
		Severity: "High",
	}
}
