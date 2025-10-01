package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var LobPubAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`, true)

func LobPubAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "46257ed4-c91d-4dcf-9d2a-81ecee35f96d",
		Description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
		RuleID:      "lob-pub-api-key",
		Regex:       LobPubAPIKeyRegex,
		Keywords: []string{
			"test_pub",
			"live_pub",
			"_pub",
		},
		Severity: "High",
	}
}
