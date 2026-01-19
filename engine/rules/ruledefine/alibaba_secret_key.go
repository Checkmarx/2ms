package ruledefine

var alibabaSecretKeyRegex = generateSemiGenericRegex([]string{"alibaba"}, AlphaNumeric("30"), true).String()

func AlibabaSecretKey() *Rule {
	// define rule
	return &Rule{
		RuleID:   "29adbc13-0261-418a-b04d-02506551295d",
		RuleName: "Alibaba-Secret-Key",
		Description: "Discovered a potential Alibaba Cloud Secret Key," +
			" potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:         alibabaSecretKeyRegex,
		Entropy:       2,
		Keywords:      []string{"alibaba"},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryCloudPlatform,
		ScoreRuleType: 4,
	}
}
