package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DigitaloceanPatRegex = utils.GenerateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`, false)

func DigitalOceanPAT() *NewRule {
	return &NewRule{
		Description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
		RuleID:      "digitalocean-pat",
		Regex:       DigitaloceanPatRegex,
		Entropy:     3,
		Keywords:    []string{"dop_v1_"},
	}
}
