package ruledefine

var dropboxAPITokenRegex = generateSemiGenericRegex([]string{"dropbox"}, AlphaNumeric("15"), true).String()

func DropBoxAPISecret() *Rule {
	return &Rule{
		RuleID:          "e20f40d2-0e7a-4b93-8206-6a7131c329c6",
		Description:     "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
		RuleName:        "dropbox-api-token",
		Regex:           dropboxAPITokenRegex,
		Keywords:        []string{"dropbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
	}
}
