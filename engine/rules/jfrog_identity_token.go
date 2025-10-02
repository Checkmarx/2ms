package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var JfrogIdentityTokenRegex = utils.GenerateSemiGenericRegex([]string{"jfrog", "artifactory", "bintray", "xray"}, utils.AlphaNumeric("64"), true)

func JFrogIdentityToken() *NewRule {
	return &NewRule{
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
