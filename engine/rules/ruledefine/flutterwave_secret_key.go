package ruledefine

import (
	"regexp"
)

var flutterwaveSecretKeyRegex = regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`).String()

func FlutterwaveSecretKey() *Rule {
	return &Rule{
		RuleID:        "3b4ec694-08bc-488c-9a5e-a4bb1ddd9f54",
		Description:   "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		RuleName:      "Flutterwave-Secret-Key",
		Regex:         flutterwaveSecretKeyRegex,
		Entropy:       2,
		Keywords:      []string{"FLWSECK_TEST"},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryPaymentProcessing,
		ScoreRuleType: 4,
	}
}
