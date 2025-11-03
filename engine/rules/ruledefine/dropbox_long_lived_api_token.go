package ruledefine

var dropboxLongLivedAPITokenRegex = generateSemiGenericRegex(
	[]string{"dropbox"}, `[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`, true).String()

func DropBoxLongLivedAPIToken() *Rule {
	return &Rule{
		RuleID:          "5e7e971a-d16a-4e9a-8a44-2d0076f54344",
		Description:     "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
		RuleName:        "Dropbox-Long-Lived-Api-Token",
		Regex:           dropboxLongLivedAPITokenRegex,
		Keywords:        []string{"dropbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
	}
}
