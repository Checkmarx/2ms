package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AlibabaSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"alibaba"}, utils.AlphaNumeric("30"), true)

func AlibabaSecretKey() *NewRule {
	// define rule
	return &NewRule{
		RuleID:      "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:       AlibabaSecretKeyRegex,
		Entropy:     2,
		Keywords:    []string{"alibaba"},
	}
}
