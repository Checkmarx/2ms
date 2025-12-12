package ruledefine

var jfrogIdentityTokenRegex = generateSemiGenericRegex(
	[]string{"jfrog", "artifactory", "bintray", "xray"}, AlphaNumeric("64"), true).String()

func JFrogIdentityToken() *Rule {
	return &Rule{
		RuleID:        "05985187-9847-4301-81a3-bce901c14dc4",
		Description:   "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",
		RuleName:      "Jfrog-Identity-Token",
		Regex:         jfrogIdentityTokenRegex,
		Keywords:      []string{"jfrog", "artifactory", "bintray", "xray"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryCICD,
		ScoreRuleType: 4,
	}
}
