package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AirtableRegex = utils.GenerateSemiGenericRegex([]string{"airtable"}, utils.AlphaNumeric("17"), true)

func Airtable() *NewRule {
	// define rule
	return &NewRule{
		Description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-api-key",
		Regex:       AirtableRegex,
		Keywords:    []string{"airtable"},
	}
}
