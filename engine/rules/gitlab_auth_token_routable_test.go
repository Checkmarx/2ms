package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabRunnerAuthenticationTokenRoutable(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabRunnerAuthenticationTokenRoutable validation",
			truePositives: []string{
				"gitlabToken = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"  \"gitlabToken\" => \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_token: \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"var gitlabToken string = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"$gitlabToken .= \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_TOKEN := \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_TOKEN ::= \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_TOKEN :::= \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_TOKEN ?= \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"string gitlabToken = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\";",
				"System.setProperty(\"GITLAB_TOKEN\", \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\")",
				"gitlab_TOKEN = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlabToken=\"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlabToken=glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo",
				"gitlabToken = glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo",
				"{\n    \"gitlab_token\": \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\\nBACKUP_ENABLED=true\"}",
				"<gitlabToken>\n    glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\n</gitlabToken>",
				"gitlabToken := \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"var gitlabToken = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlabToken = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\"",
				"gitlab_token: glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo",
				"gitlab_token: 'glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo'",
				"gitlabToken := `glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo`",
				"String gitlabToken = \"glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo\";",
				"gitlabToken = 'glrt-t1_xqh0tloxltqbz4lugf4q29nhfgt.xqxqh0tlo'",
			},
			falsePositives: []string{
				"glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx",
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
			rule := ConvertNewRuleToGitleaksRule(GitlabRunnerAuthenticationTokenRoutable())
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
