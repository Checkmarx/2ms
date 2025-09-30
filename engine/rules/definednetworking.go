package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DefinedNetworkingApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"dnkey"}, `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`, true)

func DefinedNetworkingApiToken() *NewRule {
	return &NewRule{
		Description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",
		RuleID:      "defined-networking-api-token",
		Regex:       DefinedNetworkingApiTokenRegex,

		Keywords: []string{"dnkey"},
	}
}
