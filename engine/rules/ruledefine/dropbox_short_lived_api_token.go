package ruledefine

var dropboxShortLivedAPITokenRegex = generateSemiGenericRegex(
	[]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`, true).String()

func DropBoxShortLivedAPIToken() *Rule {
	return &Rule{
		RuleID:          "e355f363-48a4-4125-b51a-4d267b81b0f8",
		Description:     "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.", //nolint:lll
		RuleName:        "Dropbox-Short-Lived-Api-Token",
		Regex:           dropboxShortLivedAPITokenRegex,
		Keywords:        []string{"dropbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
	}
}
