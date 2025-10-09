package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabRunnerAuthenticationToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabRunnerAuthenticationToken validation",
			truePositives: []string{
				"  \"gitlabToken\" => \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlab_TOKEN ::= \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken=\"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken = glrt-8wd8pimqc5nzqbcuhgp2",
				"<gitlabToken>\n    glrt-8wd8pimqc5nzqbcuhgp2\n</gitlabToken>",
				"gitlabToken := `glrt-8wd8pimqc5nzqbcuhgp2`",
				"$gitlabToken .= \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken = 'glrt-8wd8pimqc5nzqbcuhgp2'",
				"gitlab_TOKEN ?= \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken = \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"{\n    \"gitlab_token\": \"glrt-8wd8pimqc5nzqbcuhgp2\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glrt-8wd8pimqc5nzqbcuhgp2\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: 'glrt-8wd8pimqc5nzqbcuhgp2'",
				"gitlab_token: \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"string gitlabToken = \"glrt-8wd8pimqc5nzqbcuhgp2\";",
				"gitlab_TOKEN := \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlab_TOKEN :::= \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlab_token: glrt-8wd8pimqc5nzqbcuhgp2",
				"var gitlabToken string = \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken := \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"String gitlabToken = \"glrt-8wd8pimqc5nzqbcuhgp2\";",
				"gitlabToken = \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glrt-8wd8pimqc5nzqbcuhgp2\")",
				"gitlab_TOKEN = \"glrt-8wd8pimqc5nzqbcuhgp2\"",
				"gitlabToken=glrt-8wd8pimqc5nzqbcuhgp2",
				"var gitlabToken = \"glrt-8wd8pimqc5nzqbcuhgp2\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabRunnerAuthenticationToken())
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
