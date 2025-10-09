package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var TelegramBotTokenRegex = utils.GenerateSemiGenericRegex([]string{"telegr"}, "[0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34}", true)

func TelegramBotToken() *Rule {
	return &Rule{
		BaseRuleID:  "dc4163ac-6f7a-4260-9067-70764c3bdbc0",
		Description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
		RuleID:      "telegram-bot-api-token",

		Regex: TelegramBotTokenRegex,
		Keywords: []string{
			"telegr",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
