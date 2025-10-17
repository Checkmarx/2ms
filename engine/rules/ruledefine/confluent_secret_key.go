package ruledefine

var confluentSecretKeyRegex = generateSemiGenericRegex([]string{"confluent"}, AlphaNumeric("64"), true)

func ConfluentSecretKey() *Rule {
	return &Rule{
		BaseRuleID:  "ec70091b-edd6-4ba4-bb52-8871814241bc",
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		RuleID:      "confluent-secret-key",
		Regex:       confluentSecretKeyRegex.String(),

		Keywords: []string{
			"confluent",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
