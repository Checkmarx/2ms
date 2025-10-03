package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ShippoAPITokenRegex = utils.GenerateUniqueTokenRegex(`shippo_(?:live|test)_[a-fA-F0-9]{40}`, false)

func ShippoAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "f4de94a5-3aec-4b1d-8235-f165b9d8d54c",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		RuleID:      "shippo-api-token",
		Regex:       ShippoAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"shippo_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
	}
}
