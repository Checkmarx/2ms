package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DiscordApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Hex("64"), true)

func DiscordAPIToken() *NewRule {
	return &NewRule{
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		RuleID:      "discord-api-token",
		Regex:       DiscordApiTokenRegex,
		Keywords:    []string{"discord"},
	}
}
