package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var YandexAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"yandex"},
	`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`, true)

func YandexAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "b1bba54f-7da9-49a4-b057-e05dac03835a",
		Description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
		RuleID:      "yandex-access-token",
		Regex:       YandexAccessTokenRegex,
		Keywords: []string{
			"yandex",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
