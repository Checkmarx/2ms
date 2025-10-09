package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SettlemintApplicationAccessTokenRegex = utils.GenerateUniqueTokenRegex(`sm_aat_[a-zA-Z0-9]{16}`, false)

func SettlemintApplicationAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "ee89d8a5-42bd-47f1-ab61-79dd59196d1d",
		Description: "Found a Settlemint Application Access Token.",
		RuleID:      "settlemint-application-access-token",
		Regex:       SettlemintApplicationAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"sm_aat",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
	}
}
