package ruledefine

var mailChimpRegex = generateSemiGenericRegex([]string{"MailchimpSDK.initialize", "mailchimp"}, Hex("32")+`-us\d\d`, true)

func MailChimp() *Rule {
	return &Rule{
		BaseRuleID:  "04727012-1ce2-44a7-9d65-bba9d9f10fae",
		Description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
		RuleID:      "mailchimp-api-key",
		Regex:       mailChimpRegex,
		Keywords: []string{
			"mailchimp",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
