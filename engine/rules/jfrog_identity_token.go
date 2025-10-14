package rules

var JfrogIdentityTokenRegex = generateSemiGenericRegex(
	[]string{"jfrog", "artifactory", "bintray", "xray"}, AlphaNumeric("64"), true)

func JFrogIdentityToken() *Rule {
	return &Rule{
		BaseRuleID:      "05985187-9847-4301-81a3-bce901c14dc4",
		Description:     "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",
		RuleID:          "jfrog-identity-token",
		Regex:           JfrogIdentityTokenRegex,
		Keywords:        []string{"jfrog", "artifactory", "bintray", "xray"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
