package ruledefine

var authressServiceClientAccessKeyRegex = generateUniqueTokenRegex(
	`(?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}`,
	false).String()

func Authress() *Rule {
	return &Rule{
		RuleID: "f69c8e7b-e73c-45a6-8707-2fa1a807da27",
		Description: "Uncovered a possible Authress Service Client Access Key," +
			" which may compromise access control services and sensitive data.",
		RuleName:      "Authress-Service-Client-Access-Key",
		Regex:         authressServiceClientAccessKeyRegex,
		Entropy:       2,
		Keywords:      []string{"sc_", "ext_", "scauth_", "authress_"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryAuthenticationAndAuthorization,
		ScoreRuleType: 4,
	}
}
