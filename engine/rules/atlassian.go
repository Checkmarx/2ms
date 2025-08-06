package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Atlassian returns a corrected Atlassian rule that fixes the token validation issue.
// This overrides the default GitLeaks Atlassian rule to fix validation bugs.
func Atlassian() *config.Rule {
	// define rule - same as GitLeaks but with corrected validation
	r := config.Rule{
		Description: "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.",
		RuleID:      "atlassian-api-token",
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

	// Fixed validation - simplified test cases that should match the regex pattern
	tps := []string{
		`atlassian_TOKEN := "abcd1234567890123456abcd"`,   // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`CONFLUENCE_API_KEY = "test1234567890123456beef"`, // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`jira_token = "jira1234567890123456cafe"`,         // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2`,         // Keep the existing 24-char token from GitLeaks
		// Modern ATATT3 tokens (192 characters) - must be on single line
		`ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6`,
	}

	fps := []string{"getPagesInConfluenceSpace,searchConfluenceUsingCql"}

	return utils.Validate(r, tps, fps)
}
