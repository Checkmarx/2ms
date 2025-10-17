package ruledefine

import (
	"regexp"
)

var flutterwavePublicKeyRegex = regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`).String()

func FlutterwavePublicKey() *Rule {
	return &Rule{
		BaseRuleID:      "bb80218e-b84e-40cd-9481-cac01516e331",
		Description:     "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.",
		RuleID:          "flutterwave-public-key",
		Regex:           flutterwavePublicKeyRegex,
		Entropy:         2,
		Keywords:        []string{"FLWPUBK_TEST"},
		Severity:        "High",
		Tags:            []string{TagPublicKey},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
