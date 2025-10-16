package ruledefine

var algoliaRegex = generateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true)

func AlgoliaApiKey() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "3e3052a1-5be8-4ed8-90a3-f50b94c96fe5",
		Description: "Identified an Algolia API Key," +
			" which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
		RuleID:          "algolia-api-key",
		Regex:           algoliaRegex,
		Keywords:        []string{"algolia"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySearchService, RuleType: 4},
	}
}
