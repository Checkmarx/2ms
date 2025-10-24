package ruledefine

var definedNetworkingApiTokenRegex = generateSemiGenericRegex(
	[]string{"dnkey"}, `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`, true).String()

func DefinedNetworkingAPIToken() *Rule {
	return &Rule{
		RuleID:      "6175e184-12b3-44e8-acb7-9eb9733f61e1",
		Description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",
		RuleName:    "defined-networking-api-token",
		Regex:       definedNetworkingApiTokenRegex,

		Keywords:        []string{"dnkey"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
	}
}
