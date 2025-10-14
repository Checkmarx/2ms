package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitHubApp(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitHubApp validation",
			truePositives: []string{
				"githubToken=\"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"<githubToken>\n    ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\n</githubToken>",
				"String githubToken = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\";",
				"var githubToken = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"$githubToken .= \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"github_TOKEN ?= \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"{\n    \"github_token\": \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"\n}",
				"{\"config.ini\": \"GITHUB_TOKEN=ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\\nBACKUP_ENABLED=true\"}",
				"github_token: 'ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5'",
				"github_token: \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken = 'ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5'",
				"System.setProperty(\"GITHUB_TOKEN\", \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\")",
				"  \"githubToken\" => \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"github_TOKEN = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken=ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5",
				"github_token: ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5",
				"string githubToken = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\";",
				"githubToken := `ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5`",
				"githubToken = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"github_TOKEN := \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"github_TOKEN ::= \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken = ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5",
				"var githubToken string = \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken := \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"github_TOKEN :::= \"ghs_75ugvvddi4k5pa3791qc0o5b1gd9tpok90v5\"",
				"githubToken = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"System.setProperty(\"GITHUB_TOKEN\", \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\")",
				"githubToken=ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk",
				"{\"config.ini\": \"GITHUB_TOKEN=ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\\nBACKUP_ENABLED=true\"}",
				"<githubToken>\n    ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\n</githubToken>",
				"github_token: 'ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk'",
				"var githubToken string = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"String githubToken = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\";",
				"githubToken = 'ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk'",
				"  \"githubToken\" => \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"githubToken = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_token: \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"githubToken := \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"var githubToken = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_TOKEN := \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_TOKEN ::= \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_TOKEN :::= \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"githubToken=\"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_token: ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk",
				"string githubToken = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\";",
				"githubToken := `ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk`",
				"$githubToken .= \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_TOKEN = \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"github_TOKEN ?= \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"",
				"githubToken = ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk",
				"{\n    \"github_token\": \"ghu_bn3j90rbp5wrhpr57i1jxj1d28jtg3yerjbk\"\n}",
			},
			falsePositives: []string{
				"ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitHubApp())
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
