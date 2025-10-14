package rules

var NewRelicInsertKeyRegex = generateSemiGenericRegex([]string{
	"new-relic",
	"newrelic",
	"new_relic",
}, `NRII-[a-z0-9-]{32}`, true)

func NewRelicInsertKey() *Rule {
	return &Rule{
		BaseRuleID:  "3ba5a85e-a516-4b94-8cb6-714cecc08a18",
		Description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
		RuleID:      "new-relic-insert-key",
		Regex:       NewRelicInsertKeyRegex,
		Keywords: []string{
			"NRII-",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
