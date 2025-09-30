package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DigitaloceanAccessTokenRegex = utils.GenerateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`, false)

func DigitalOceanOAuthToken() *NewRule {
	return &NewRule{
		Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
		RuleID:      "digitalocean-access-token",
		Regex:       DigitaloceanAccessTokenRegex,
		Entropy:     3,
		Keywords:    []string{"doo_v1_"},
	}
}
