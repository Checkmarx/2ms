package ruledefine

var lobPubAPIKeyRegex = generateSemiGenericRegex(
	[]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`, true).String()

func LobPubAPIToken() *Rule {
	return &Rule{
		RuleID:      "46257ed4-c91d-4dcf-9d2a-81ecee35f96d",
		Description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
		RuleName:    "Lob-Pub-Api-Key",
		Regex:       lobPubAPIKeyRegex,
		Keywords: []string{
			"test_pub",
			"live_pub",
			"_pub",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
