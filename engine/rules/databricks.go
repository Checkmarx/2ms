package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DatabricksApiTokenRegex = utils.GenerateUniqueTokenRegex(`dapi[a-f0-9]{32}(?:-\d)?`, false)

func Databricks() *NewRule {
	return &NewRule{
		BaseRuleID:  "0d6c06db-760d-4414-920e-4f1670c23169",
		Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		RuleID:      "databricks-api-token",
		Regex:       DatabricksApiTokenRegex,
		Severity:    "High",
		Entropy:     3,
		Keywords:    []string{"dapi"},
	}
}
