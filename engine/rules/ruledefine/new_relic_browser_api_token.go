package ruledefine

var newRelicBrowserAPITokenRegex = generateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, `NRJS-[a-f0-9]{19}`, true).String()

func NewRelicBrowserAPIKey() *Rule {
	return &Rule{
		RuleID: "ed7aad7a-82e5-41c4-b3ba-b8e61fa410fd",
		Description: "Identified a New Relic ingest browser API token," +
			" risking unauthorized access to application performance data and analytics.",
		RuleName: "New-Relic-Browser-Api-Token",
		Regex:    newRelicBrowserAPITokenRegex,
		Keywords: []string{
			"NRJS-",
		},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryApplicationMonitoring,
		ScoreRuleType: 4,
	}
}
