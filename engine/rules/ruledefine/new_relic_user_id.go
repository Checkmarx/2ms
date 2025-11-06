package ruledefine

var newRelicUserAPIKeyRegex = generateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, `NRAK-[a-z0-9]{27}`, true).String()

func NewRelicUserID() *Rule {
	return &Rule{
		RuleID:      "bd7d9fd6-896f-49f2-874e-310f950f0057",
		Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
		RuleName:    "New-Relic-User-Api-Key",
		Regex:       newRelicUserAPIKeyRegex,
		Keywords: []string{
			"NRAK",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 1},
	}
}
