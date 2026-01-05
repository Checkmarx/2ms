package ruledefine

var jfrogAPIKeyRegex = generateSemiGenericRegex([]string{
	"jfrog", "artifactory", "bintray", "xray"}, AlphaNumeric("73"), true).String()

func JFrogAPIKey() *Rule {
	return &Rule{
		RuleID:        "29d1757d-b8a9-4a1c-aec5-79d32cfc1a62",
		Description:   "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",
		RuleName:      "Jfrog-Api-Key",
		Regex:         jfrogAPIKeyRegex,
		Keywords:      []string{"jfrog", "artifactory", "bintray", "xray"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryCICD,
		ScoreRuleType: 4,
	}
}
