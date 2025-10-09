package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var TwitterAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("25"), true)

func TwitterAPIKey() *Rule {
	return &Rule{
		BaseRuleID:      "92c1a521-9332-488c-b323-b70a280c499f",
		Description:     "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
		RuleID:          "twitter-api-key",
		Regex:           TwitterAPIKeyRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
