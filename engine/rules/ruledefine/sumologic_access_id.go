package ruledefine

var sumoLogicAccessIDRegex = generateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false).String()

func SumoLogicAccessID() *Rule {
	return &Rule{
		RuleID:      "52046e20-135d-4ac9-9198-384c0f20cfa5",
		RuleName:    "Sumologic-Access-Id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		Regex:       sumoLogicAccessIDRegex,
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
		Severity:      "High",
		Tags:          []string{TagAccessId},
		Category:      CategoryApplicationMonitoring,
		ScoreRuleType: 4,
	}
}
