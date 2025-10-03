package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGithubFineGrainedPAT(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitHubFineGrainedPat validation",
			truePositives: []string{
				"githubToken=\"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\"",
				"{\"config.ini\": \"GITHUB_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"github_token: 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",
				"github_token: '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'",
				"githubToken := \"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\"",
				"String githubToken = \"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\";",
				"githubToken = \"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\"",
				"System.setProperty(\"GITHUB_TOKEN\", \"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\")",
				"githubToken = \"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\"",
				"string githubToken = \"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\";",
				"githubToken := `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`",
				"var githubToken = \"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\"",
				"githubToken = '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'",
				"github_TOKEN :::= \"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\"",
				"github_TOKEN ?= \"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\"",
				"<githubToken>\n    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\n</githubToken>",
				"var githubToken string = \"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\"",
				"github_TOKEN = \"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\"",
				"github_TOKEN ::= \"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\"",
				"githubToken=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",
				"githubToken = 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",
				"{\n    \"github_token\": \"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\"\n}",
				"github_token: \"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\"",
				"$githubToken .= \"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\"",
				"  \"githubToken\" => \"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\"",
				"github_TOKEN := \"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\"",
			},
			falsePositives: []string{
				"github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
			rule := ConvertNewRuleToGitleaksRule(GitHubFineGrainedPat())
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
