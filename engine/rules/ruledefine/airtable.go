package ruledefine

var airtableRegex = generateSemiGenericRegex([]string{"airtable"}, AlphaNumeric("17"), true).String()

func Airtable() *Rule {
	// define rule
	return &Rule{
		RuleID: "6869a35b-dfad-439d-b285-3b26a4469224",
		Description: "Uncovered a possible Airtable API Key," +
			" potentially compromising database access and leading to data leakage or alteration.",
		RuleName:        "Airtable-Api-Key",
		Regex:           airtableRegex,
		Keywords:        []string{"airtable"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
