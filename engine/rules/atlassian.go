package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Atlassian() *config.Rule {
	return &config.Rule{
		Description: `Detected an Atlassian API token, 
			posing a threat to project management and 
			collaboration tool security and data confidentiality.`,
		RuleID: "atlassian-api-token",
		Regex: utils.MergeRegexps(
			utils.GenerateSemiGenericRegex(
				[]string{"(?-i:ATLASSIAN|[Aa]tlassian)", "(?-i:CONFLUENCE|[Cc]onfluence)", "(?-i:JIRA|[Jj]ira)"},
				`[a-z0-9]{20}[a-f0-9]{4}`, // The last 4 characters are an MD5 hash.
				true,
			),
			utils.GenerateUniqueTokenRegex(`ATATT3[A-Za-z0-9_\-=]{186}`, false),
		),
		Entropy:  3.5,
		Keywords: []string{"atlassian", "confluence", "jira", "atatt3"},
	}
}
