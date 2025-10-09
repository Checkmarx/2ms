package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AirtableRegex = utils.GenerateSemiGenericRegex([]string{"airtable"}, utils.AlphaNumeric("17"), true)

func Airtable() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "6869a35b-dfad-439d-b285-3b26a4469224",
		Description: "Uncovered a possible Airtable API Key," +
			" potentially compromising database access and leading to data leakage or alteration.",
		RuleID:          "airtable-api-key",
		Regex:           AirtableRegex,
		Keywords:        []string{"airtable"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
