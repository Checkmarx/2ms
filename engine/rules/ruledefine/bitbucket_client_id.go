package ruledefine

var bitbucketClientIdRegex = generateSemiGenericRegex([]string{"bitbucket"}, AlphaNumeric("32"), true)

func BitBucketClientID() *Rule {
	return &Rule{
		BaseRuleID:      "adc652bc-4f17-48b6-8f23-fd3aca2a31e3",
		Description:     "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:          "bitbucket-client-id",
		Regex:           bitbucketClientIdRegex,
		Keywords:        []string{"bitbucket"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 1},
	}
}
