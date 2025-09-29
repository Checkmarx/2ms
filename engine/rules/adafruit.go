package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

// regex for rule
var AdafruitAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"adafruit"}, utils.AlphaNumericExtendedShort("32"), true)

func AdafruitAPIKey() *NewRule {
	// define rule
	return &NewRule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Regex:       AdafruitAPIKeyRegex,
		Keywords:    []string{"adafruit"},
	}
}
