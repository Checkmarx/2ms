package ruledefine

var newRelicUserAPIIDRegex = generateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, AlphaNumeric("64"), true).String()

func NewRelicUserKey() *Rule {
	return &Rule{
		BaseRuleID:  "12d84d93-c459-4ce9-9b42-56c92753776f",
		Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
		RuleID:      "new-relic-user-api-id",
		Regex:       newRelicUserAPIIDRegex,
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
