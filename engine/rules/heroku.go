package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var HerokuAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"heroku"}, utils.Hex8_4_4_4_12(), true)

func Heroku() *NewRule {
	return &NewRule{
		BaseRuleID:  "4590b0c1-a67f-4fd5-b949-51e844cff884",
		Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "heroku-api-key",
		Regex:       HerokuAPIKeyRegex,
		Keywords:    []string{"heroku"},
		Severity:    "High",
	}
}
