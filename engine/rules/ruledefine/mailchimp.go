package ruledefine

var mailChimpRegex = generateSemiGenericRegex(
	[]string{"MailchimpSDK.initialize", "mailchimp"}, Hex("32")+`-us\d\d`, true).String()

func MailChimp() *Rule {
	return &Rule{
		RuleID:      "04727012-1ce2-44a7-9d65-bba9d9f10fae",
		Description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
		RuleName:    "Mailchimp-Api-Key",
		Regex:       mailChimpRegex,
		Keywords: []string{
			"mailchimp",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
