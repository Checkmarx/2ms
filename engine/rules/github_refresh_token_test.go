package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGithubRefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitHubRefresh validation",
			truePositives: []string{
				"githubToken=ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8",
				"{\"config.ini\": \"GITHUB_TOKEN=ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\\nBACKUP_ENABLED=true\"}",
				"var githubToken string = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"var githubToken = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"System.setProperty(\"GITHUB_TOKEN\", \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\")",
				"  \"githubToken\" => \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"github_TOKEN := \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"<githubToken>\n    ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\n</githubToken>",
				"githubToken := \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"githubToken := `ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8`",
				"github_TOKEN :::= \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"githubToken = ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8",
				"string githubToken = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\";",
				"githubToken = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"github_TOKEN = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"github_TOKEN ::= \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"github_TOKEN ?= \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"githubToken=\"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"{\n    \"github_token\": \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"\n}",
				"github_token: ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8",
				"github_token: 'ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8'",
				"github_token: \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"String githubToken = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\";",
				"$githubToken .= \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
				"githubToken = 'ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8'",
				"githubToken = \"ghr_g2gv180f1z5a25zsgvxvdb9i02vubb5x4jx8\"",
			},
			falsePositives: []string{
				"ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(GitHubRefresh())
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
