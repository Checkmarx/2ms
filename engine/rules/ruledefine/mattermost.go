package ruledefine

var mattermostAccessTokenRegex = generateSemiGenericRegex([]string{"mattermost"}, AlphaNumeric("26"), true).String()

func MattermostAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "33177814-840a-4057-a281-4c3514a9fcdb",
		Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
		RuleID:      "mattermost-access-token",
		Regex:       mattermostAccessTokenRegex,
		Keywords: []string{
			"mattermost",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
