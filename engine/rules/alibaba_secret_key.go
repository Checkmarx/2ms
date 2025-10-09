package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AlibabaSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"alibaba"}, utils.AlphaNumeric("30"), true)

func AlibabaSecretKey() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "29adbc13-0261-418a-b04d-02506551295d",
		RuleID:     "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key," +
			" potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:           AlibabaSecretKeyRegex,
		Entropy:         2,
		Keywords:        []string{"alibaba"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
