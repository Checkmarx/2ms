package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var JfrogAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"jfrog", "artifactory", "bintray", "xray"}, utils.AlphaNumeric("73"), true)

func JfrogAPIKey() *NewRule {
	return &NewRule{
		BaseRuleID:  "29d1757d-b8a9-4a1c-aec5-79d32cfc1a62",
		Description: "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",
		RuleID:      "jfrog-api-key",
		Regex:       JfrogAPIKeyRegex,
		Keywords:    []string{"jfrog", "artifactory", "bintray", "xray"},
		Severity:    "High",
	}
}
