package ruledefine

var PulumiAPITokenRegex = generateUniqueTokenRegex(`pul-[a-f0-9]{40}`, false)

func PulumiAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "a106c89b-68ed-47a6-ac7f-ef2fa78cfef2",
		Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
		RuleID:      "pulumi-api-token",
		Regex:       PulumiAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"pul-",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
