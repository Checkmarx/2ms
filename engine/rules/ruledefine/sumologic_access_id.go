package ruledefine

var SumoLogicAccessIDRegex = generateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false)

func SumoLogicAccessID() *Rule {
	return &Rule{
		BaseRuleID:  "52046e20-135d-4ac9-9198-384c0f20cfa5",
		RuleID:      "sumologic-access-id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		Regex:       SumoLogicAccessIDRegex,
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
		Severity:        "High",
		Tags:            []string{TagAccessId},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
