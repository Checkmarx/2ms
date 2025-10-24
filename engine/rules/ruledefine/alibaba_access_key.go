package ruledefine

var alibabaAccessKeyRegex = generateUniqueTokenRegex(`LTAI(?i)[a-z0-9]{20}`, false).String()

func AlibabaAccessKey() *Rule {
	// define rule
	return &Rule{
		RuleID:   "a093db05-dd07-4cb5-a387-05749c098546",
		RuleName: "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID," +
			" posing a risk of unauthorized cloud resource access and potential data compromise.",
		Regex:           alibabaAccessKeyRegex,
		Entropy:         2,
		Keywords:        []string{"LTAI"},
		Severity:        "High",
		Tags:            []string{TagAccessKey, TagAccessId},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 1},
	}
}
