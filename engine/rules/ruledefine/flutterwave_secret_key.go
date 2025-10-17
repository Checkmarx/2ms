package ruledefine

import (
	"regexp"
)

var flutterwaveSecretKeyRegex = regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`).String()

func FlutterwaveSecretKey() *Rule {
	return &Rule{
		BaseRuleID:      "3b4ec694-08bc-488c-9a5e-a4bb1ddd9f54",
		Description:     "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		RuleID:          "flutterwave-secret-key",
		Regex:           flutterwaveSecretKeyRegex,
		Entropy:         2,
		Keywords:        []string{"FLWSECK_TEST"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
