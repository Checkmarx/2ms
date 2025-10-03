package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SnykRegex = utils.GenerateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, utils.Hex8_4_4_4_12(), true)

func Snyk() *NewRule {
	return &NewRule{
		BaseRuleID:      "152b3ca6-408d-4b3b-b5b9-1f74f00df88e",
		Description:     "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:          "snyk-api-token",
		Regex:           SnykRegex,
		Keywords:        []string{"snyk"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
	}
}
