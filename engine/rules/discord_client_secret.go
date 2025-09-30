package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DiscordClientSecretRegex = utils.GenerateSemiGenericRegex([]string{"discord"}, utils.AlphaNumericExtended("32"), true)

func DiscordClientSecret() *NewRule {
	return &NewRule{
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		RuleID:      "discord-client-secret",
		Regex:       DiscordClientSecretRegex,
		Entropy:     2,
		Keywords:    []string{"discord"},
	}
}
