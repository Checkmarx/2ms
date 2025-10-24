package ruledefine

var shippoAPITokenRegex = generateUniqueTokenRegex(`shippo_(?:live|test)_[a-fA-F0-9]{40}`, false).String()

func ShippoAPIToken() *Rule {
	return &Rule{
		RuleID:      "f4de94a5-3aec-4b1d-8235-f165b9d8d54c",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		RuleName:    "shippo-api-token",
		Regex:       shippoAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"shippo_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
	}
}
