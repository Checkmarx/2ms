package ruledefine

var zendeskSecretKeyRegex = generateSemiGenericRegex([]string{"zendesk"}, AlphaNumeric("40"), true).String()

func ZendeskSecretKey() *Rule {
	return &Rule{
		RuleID:      "ef6ad1b6-cb89-44a9-9e70-783095456d62",
		Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
		RuleName:    "Zendesk-Secret-Key",
		Regex:       zendeskSecretKeyRegex,
		Keywords: []string{
			"zendesk",
		},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryCustomerSupport,
		ScoreRuleType: 4,
	}
}
