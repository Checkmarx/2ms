package ruledefine

var mailgunPubKeyRegex = generateSemiGenericRegex([]string{"mailgun"}, `pubkey-[a-f0-9]{32}`, true).String()

func MailGunPubAPIToken() *Rule {
	return &Rule{
		RuleID:      "83133dbd-e5b6-4b5c-a37d-78e1c45abeac",
		Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
		RuleName:    "Mailgun-Pub-Key",
		Regex:       mailgunPubKeyRegex,
		Keywords: []string{
			"mailgun",
		},
		Severity:        "High",
		Tags:            []string{TagPublicKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
