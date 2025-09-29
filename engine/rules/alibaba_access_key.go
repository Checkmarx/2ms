package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AlibabaAccessKeyRegex = utils.GenerateUniqueTokenRegex(`LTAI(?i)[a-z0-9]{20}`, false)

func AlibabaAccessKey() *NewRule {
	// define rule
	return &NewRule{
		RuleID:      "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		Regex:       AlibabaAccessKeyRegex,
		Entropy:     2,
		Keywords:    []string{"LTAI"},
	}
}
