package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DefinedNetworkingApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"dnkey"}, `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`, true)

func DefinedNetworkingAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "6175e184-12b3-44e8-acb7-9eb9733f61e1",
		Description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",
		RuleID:      "defined-networking-api-token",
		Regex:       DefinedNetworkingApiTokenRegex,

		Keywords:        []string{"dnkey"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
	}
}
