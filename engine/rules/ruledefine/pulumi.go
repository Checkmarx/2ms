package ruledefine

var pulumiAPITokenRegex = generateUniqueTokenRegex(`pul-[a-f0-9]{40}`, false).String()

func PulumiAPIToken() *Rule {
	return &Rule{
		RuleID:      "a106c89b-68ed-47a6-ac7f-ef2fa78cfef2",
		Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
		RuleName:    "pulumi-api-token",
		Regex:       pulumiAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"pul-",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
