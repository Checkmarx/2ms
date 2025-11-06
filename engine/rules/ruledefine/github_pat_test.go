package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGithubPAT(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitHubPat validation",
			truePositives: []string{
				"githubToken=\"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"githubToken = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"githubToken = ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q",
				"{\n    \"github_token\": \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"\n}",
				"github_token: 'ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q'",
				"githubToken := `ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q`",
				"String githubToken = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\";",
				"github_token: ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q",
				"var githubToken string = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"githubToken := \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"$githubToken .= \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"githubToken = 'ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q'",
				"  \"githubToken\" => \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"github_TOKEN ::= \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"githubToken=ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q",
				"{\"config.ini\": \"GITHUB_TOKEN=ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\\nBACKUP_ENABLED=true\"}",
				"<githubToken>\n    ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\n</githubToken>",
				"githubToken = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"System.setProperty(\"GITHUB_TOKEN\", \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\")",
				"github_TOKEN = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"github_TOKEN ?= \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"github_token: \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"string githubToken = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\";",
				"var githubToken = \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"github_TOKEN := \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
				"github_TOKEN :::= \"ghp_botnfvvnp3k9fhb107idtkgpwbccjw8wum5q\"",
			},
			falsePositives: []string{
				"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitHubPat())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
