package secrets

type CustomRuleConfiguration struct {
	Description  string
	RegexPattern string
	RuleID       string
	Tags         []string
	SecretGroup  int
}

var customRules = []CustomRuleConfiguration{
	{
		Description:  "Identify username:password inside URLS",
		RuleID:       "username-password-secret",
		RegexPattern: ":\\/\\/(.+:.+)?@",
		Tags:         []string{TagPassword},
		SecretGroup:  1,
	},
}
