package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabPatRoutable(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabPatRoutable validation",
			truePositives: []string{
				"gitlabToken = glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8",
				"{\n    \"gitlab_token\": \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\\nBACKUP_ENABLED=true\"}",
				"<gitlabToken>\n    glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\n</gitlabToken>",
				"string gitlabToken = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\";",
				"var gitlabToken string = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlabToken := \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\")",
				"gitlab_token: 'glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8'",
				"String gitlabToken = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\";",
				"gitlabToken = 'glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8'",
				"  \"gitlabToken\" => \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_TOKEN ::= \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_TOKEN :::= \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlabToken = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_token: glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8",
				"gitlabToken := `glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8`",
				"var gitlabToken = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"$gitlabToken .= \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlabToken=\"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlabToken=glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8",
				"gitlab_token: \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlabToken = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_TOKEN = \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_TOKEN := \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
				"gitlab_TOKEN ?= \"glpat-0thvkg8tnsqpnek96k0pa3latn9.0t0thvkg8\"",
			},
			falsePositives: []string{
				"glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabPatRoutable())
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
