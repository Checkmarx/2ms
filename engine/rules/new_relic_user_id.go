package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NewRelicUserAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, `NRAK-[a-z0-9]{27}`, true)

func NewRelicUserID() *NewRule {
	return &NewRule{
		BaseRuleID:  "bd7d9fd6-896f-49f2-874e-310f950f0057",
		Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
		RuleID:      "new-relic-user-api-key",
		Regex:       NewRelicUserAPIKeyRegex,
		Keywords: []string{
			"NRAK",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 1},
	}
}
