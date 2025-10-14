package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabPat(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabPat validation",
			truePositives: []string{
				"{\n    \"gitlab_token\": \"glpat-ujkk226tkqcxwmh838id\"\n}",
				"<gitlabToken>\n    glpat-ujkk226tkqcxwmh838id\n</gitlabToken>",
				"$gitlabToken .= \"glpat-ujkk226tkqcxwmh838id\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glpat-ujkk226tkqcxwmh838id\")",
				"gitlabToken=glpat-ujkk226tkqcxwmh838id",
				"gitlabToken = glpat-ujkk226tkqcxwmh838id",
				"{\"config.ini\": \"GITLAB_TOKEN=glpat-ujkk226tkqcxwmh838id\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: glpat-ujkk226tkqcxwmh838id",
				"string gitlabToken = \"glpat-ujkk226tkqcxwmh838id\";",
				"var gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN :::= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_token: \"glpat-ujkk226tkqcxwmh838id\"",
				"var gitlabToken string = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken := \"glpat-ujkk226tkqcxwmh838id\"",
				"String gitlabToken = \"glpat-ujkk226tkqcxwmh838id\";",
				"gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN := \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN ?= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_token: 'glpat-ujkk226tkqcxwmh838id'",
				"gitlabToken := `glpat-ujkk226tkqcxwmh838id`",
				"gitlabToken = 'glpat-ujkk226tkqcxwmh838id'",
				"  \"gitlabToken\" => \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN ::= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken=\"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
			},
			falsePositives: []string{
				"glpat-XXXXXXXXXXX-XXXXXXXX",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabPat())
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
