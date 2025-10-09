package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var LobAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`, true)

func LobAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "31d3de85-1e14-459a-af28-3cf541972e3b",
		Description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
		RuleID:      "lob-api-key",
		Regex:       LobAPIKeyRegex,
		Keywords: []string{
			"test_",
			"live_",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
