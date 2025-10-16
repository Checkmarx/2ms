package ruledefine

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var atlassianRegex = utils.MergeRegexps(
	generateSemiGenericRegex(
		[]string{"(?-i:ATLASSIAN|[Aa]tlassian)", "(?-i:CONFLUENCE|[Cc]onfluence)", "(?-i:JIRA|[Jj]ira)"},
		`[a-z0-9]{20}[a-f0-9]{4}`, // The last 4 characters are an MD5 hash.
		true,
	),
	generateUniqueTokenRegex(`ATATT3[A-Za-z0-9_\-=]{186}`, false),
)

func Atlassian() *Rule {
	return &Rule{
		BaseRuleID: "d8bd5d5b-c6b2-4d7d-877b-d73947e2139a",
		Description: `Detected an Atlassian API token, 
			posing a threat to project management and 
			collaboration tool security and data confidentiality.`,
		RuleID:          "atlassian-api-token",
		Regex:           atlassianRegex,
		Entropy:         3.5,
		Keywords:        []string{"atlassian", "confluence", "jira", "atatt3"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
	}
}
