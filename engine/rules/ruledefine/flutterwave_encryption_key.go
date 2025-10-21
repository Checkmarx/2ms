package ruledefine

import (
	"regexp"
)

var flutterwaveEncryptionKeyRegex = regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`).String()

func FlutterwaveEncKey() *Rule {
	return &Rule{
		BaseRuleID:      "cb1219fe-fef7-4a5d-81e2-d12164e5e7fc",
		Description:     "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
		RuleID:          "flutterwave-encryption-key",
		Regex:           flutterwaveEncryptionKeyRegex,
		Entropy:         2,
		Keywords:        []string{"FLWSECK_TEST"},
		Severity:        "High",
		Tags:            []string{TagEncryptionKey},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
