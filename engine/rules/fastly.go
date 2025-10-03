package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var FastlyAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"fastly"}, utils.AlphaNumericExtended("32"), true)

func FastlyAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "698e8f80-f409-4a03-99d1-cf4891ce7479",
		Description:     "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleID:          "fastly-api-token",
		Regex:           FastlyAPITokenRegex,
		Keywords:        []string{"fastly"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
	}
}
