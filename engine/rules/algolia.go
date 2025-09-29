package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AlgoliaRegex = utils.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true)

func AlgoliaApiKey() *NewRule {
	// define rule
	return &NewRule{
		Description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
		RuleID:      "algolia-api-key",
		Regex:       AlgoliaRegex,
		Keywords:    []string{"algolia"},
	}
}
