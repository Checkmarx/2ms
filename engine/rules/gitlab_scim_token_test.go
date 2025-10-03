package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabScimToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabScimToken validation",
			truePositives: []string{
				"String gitlabToken = \"glsoat-b1h23bxl7qhsyt9svh3v\";",
				"gitlab_TOKEN = \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlab_TOKEN ::= \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlabToken=\"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlabToken = \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"var gitlabToken = \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"$gitlabToken .= \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlab_TOKEN ?= \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"{\"config.ini\": \"GITLAB_TOKEN=glsoat-b1h23bxl7qhsyt9svh3v\\nBACKUP_ENABLED=true\"}",
				"string gitlabToken = \"glsoat-b1h23bxl7qhsyt9svh3v\";",
				"var gitlabToken string = \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlabToken := \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlabToken = 'glsoat-b1h23bxl7qhsyt9svh3v'",
				"System.setProperty(\"GITLAB_TOKEN\", \"glsoat-b1h23bxl7qhsyt9svh3v\")",
				"gitlabToken=glsoat-b1h23bxl7qhsyt9svh3v",
				"<gitlabToken>\n    glsoat-b1h23bxl7qhsyt9svh3v\n</gitlabToken>",
				"gitlab_token: 'glsoat-b1h23bxl7qhsyt9svh3v'",
				"gitlabToken := `glsoat-b1h23bxl7qhsyt9svh3v`",
				"gitlabToken = \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"  \"gitlabToken\" => \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlab_TOKEN := \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlab_TOKEN :::= \"glsoat-b1h23bxl7qhsyt9svh3v\"",
				"gitlabToken = glsoat-b1h23bxl7qhsyt9svh3v",
				"{\n    \"gitlab_token\": \"glsoat-b1h23bxl7qhsyt9svh3v\"\n}",
				"gitlab_token: glsoat-b1h23bxl7qhsyt9svh3v",
				"gitlab_token: \"glsoat-b1h23bxl7qhsyt9svh3v\"",
			},
			falsePositives: []string{},
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
			rule := ConvertNewRuleToGitleaksRule(GitlabScimToken())
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
