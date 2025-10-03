package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CiscoMerakiAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{`(?-i:[Mm]eraki|MERAKI)`}, `[0-9a-f]{40}`, false)

func Meraki() *NewRule {
	return &NewRule{
		BaseRuleID:      "bf05ece5-600c-4012-b115-70a9c5bead23",
		Description:     "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
		RuleID:          "cisco-meraki-api-key",
		Regex:           CiscoMerakiAPIKeyRegex,
		Entropy:         3,
		Keywords:        []string{"meraki"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
	}
}
