package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DigitaloceanAccessTokenRegex = utils.GenerateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`, false)

func DigitalOceanOAuthToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "25360df5-249a-4889-a08a-011d0d5dc7a5",
		Description:     "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
		RuleID:          "digitalocean-access-token",
		Regex:           DigitaloceanAccessTokenRegex,
		Entropy:         3,
		Keywords:        []string{"doo_v1_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
