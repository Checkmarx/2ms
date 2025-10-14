package rules

var NewRelicBrowserAPITokenRegex = generateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, `NRJS-[a-f0-9]{19}`, true)

func NewRelicBrowserAPIKey() *Rule {
	return &Rule{
		BaseRuleID: "ed7aad7a-82e5-41c4-b3ba-b8e61fa410fd",
		Description: "Identified a New Relic ingest browser API token," +
			" risking unauthorized access to application performance data and analytics.",
		RuleID: "new-relic-browser-api-token",
		Regex:  NewRelicBrowserAPITokenRegex,
		Keywords: []string{
			"NRJS-",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
