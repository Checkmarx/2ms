package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DiscordClientIdRegex = utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Numeric("18"), true)

func DiscordClientID() *NewRule {
	return &NewRule{
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		RuleID:      "discord-client-id",
		Regex:       DiscordClientIdRegex,
		Entropy:     2,
		Keywords:    []string{"discord"},
	}
}
