package ruledefine

var sendbirdAccessIDRegex = generateSemiGenericRegex([]string{"sendbird"}, Hex8_4_4_4_12(), true).String()

func SendbirdAccessID() *Rule {
	return &Rule{
		RuleID:      "74bd716d-2bb3-4e13-bda3-e56c9a058726",
		Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
		RuleName:    "Sendbird-Access-Id",
		Regex:       sendbirdAccessIDRegex,
		Keywords: []string{
			"sendbird",
		},
		Severity:      "High",
		Tags:          []string{TagAccessId},
		Category:      CategorySocialMedia,
		ScoreRuleType: 1,
	}
}
