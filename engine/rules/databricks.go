package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DatabricksApiTokenRegex = utils.GenerateUniqueTokenRegex(`dapi[a-f0-9]{32}(?:-\d)?`, false)

func DatabricksApiToken() *NewRule {
	return &NewRule{
		Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		RuleID:      "databricks-api-token",
		Regex:       DatabricksApiTokenRegex,
		Entropy:     3,
		Keywords:    []string{"dapi"},
	}
}
