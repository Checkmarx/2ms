package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NewRelicUserAPIIDRegex = utils.GenerateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, utils.AlphaNumeric("64"), true)

func NewRelicUserKey() *NewRule {
	return &NewRule{
		BaseRuleID:  "12d84d93-c459-4ce9-9b42-56c92753776f",
		Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
		RuleID:      "new-relic-user-api-id",
		Regex:       NewRelicUserAPIIDRegex,
		Keywords: []string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
		Severity:        "High",
		Tags:            []string{TagAccessId},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
