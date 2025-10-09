package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var HerokuAPIKeyV2Regex = utils.GenerateUniqueTokenRegex(`(HRKU-AA[0-9a-zA-Z_-]{58})`, false)

func HerokuV2() *Rule {
	return &Rule{
		BaseRuleID:      "fcbe029b-6784-4636-aad4-ea982f6e010b",
		Description:     "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:          "heroku-api-key-v2",
		Regex:           HerokuAPIKeyV2Regex,
		Entropy:         4,
		Keywords:        []string{"HRKU-AA"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
