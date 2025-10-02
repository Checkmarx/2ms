package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var FlutterwaveSecretKeyRegex = regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`)

func FlutterwaveSecretKey() *NewRule {
	return &NewRule{
		BaseRuleID:      "3b4ec694-08bc-488c-9a5e-a4bb1ddd9f54",
		Description:     "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		RuleID:          "flutterwave-secret-key",
		Regex:           FlutterwaveSecretKeyRegex,
		Entropy:         2,
		Keywords:        []string{"FLWSECK_TEST"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
