package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGithubOauth(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GithubOauth validation",
			truePositives: []string{
				"githubToken = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken = gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e",
				"<githubToken>\n    gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\n</githubToken>",
				"System.setProperty(\"GITHUB_TOKEN\", \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\")",
				"  \"githubToken\" => \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"github_TOKEN := \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"{\n    \"github_token\": \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"\n}",
				"github_token: gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e",
				"github_token: \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken := `gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e`",
				"String githubToken = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\";",
				"githubToken = 'gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e'",
				"{\"config.ini\": \"GITHUB_TOKEN=gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\\nBACKUP_ENABLED=true\"}",
				"string githubToken = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\";",
				"github_TOKEN = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"github_TOKEN ::= \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"github_TOKEN :::= \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"github_TOKEN ?= \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken=\"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken=gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e",
				"github_token: 'gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e'",
				"var githubToken string = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"githubToken := \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"var githubToken = \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
				"$githubToken .= \"gho_tizalr108n3gvdhtjx18bvqz0zupu7ymog9e\"",
			},
			falsePositives: []string{
				"gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
			rule := ConvertNewRuleToGitleaksRule(GithubOauth())
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
