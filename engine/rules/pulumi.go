package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var PulumiAPITokenRegex = utils.GenerateUniqueTokenRegex(`pul-[a-f0-9]{40}`, false)

func PulumiAPIToken() *NewRule {
	return &NewRule{
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
