package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DigitaloceanRefreshTokenRegex = utils.GenerateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true)

func DigitalOceanRefreshToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "38567389-ffda-4c25-b717-486b945027c4",
		Description:     "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
		RuleID:          "digitalocean-refresh-token",
		Regex:           DigitaloceanRefreshTokenRegex,
		Keywords:        []string{"dor_v1_"},
		Severity:        "High",
		Tags:            []string{TagRefreshToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
