package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabPipelineTriggerToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabPipelineTriggerToken validation",
			truePositives: []string{
				"gitlabToken=glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9",
				"{\n    \"gitlab_token\": \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"\n}",
				"<gitlabToken>\n    glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\n</gitlabToken>",
				"gitlab_token: glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9",
				"gitlabToken := `glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9`",
				"var gitlabToken = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"  \"gitlabToken\" => \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlab_TOKEN = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlab_token: 'glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9'",
				"gitlab_token: \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlabToken := \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"$gitlabToken .= \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlabToken = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlab_TOKEN :::= \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlab_TOKEN ?= \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlabToken = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlabToken = glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9",
				"string gitlabToken = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\";",
				"var gitlabToken string = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",

				"String gitlabToken = \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\";",
				"gitlabToken = 'glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9'",
				"gitlab_TOKEN := \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"gitlabToken=\"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
				"{\"config.ini\": \"GITLAB_TOKEN=glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\\nBACKUP_ENABLED=true\"}",
				"System.setProperty(\"GITLAB_TOKEN\", \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\")",
				"gitlab_TOKEN ::= \"glptt-2c751ef2990b92403ccbfc9652c55b8cb24bf5d9\"",
			},
			falsePositives: []string{
				"glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
			rule := ConvertNewRuleToGitleaksRule(GitlabPipelineTriggerToken())
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
