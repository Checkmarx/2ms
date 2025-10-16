package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabCiCdJobToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabCiCdJobToken validation",
			truePositives: []string{
				"  \"gitlabToken\" => \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_TOKEN :::= \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_TOKEN ?= \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlabToken = \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_token: 'glcbt-fakru_fakru057x78545lqtm5q'",
				"string gitlabToken = \"glcbt-fakru_fakru057x78545lqtm5q\";",
				"var gitlabToken = \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"$gitlabToken .= \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlabToken = 'glcbt-fakru_fakru057x78545lqtm5q'",
				"gitlabToken=\"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlabToken=glcbt-fakru_fakru057x78545lqtm5q",
				"<gitlabToken>\n    glcbt-fakru_fakru057x78545lqtm5q\n</gitlabToken>",
				"gitlabToken := `glcbt-fakru_fakru057x78545lqtm5q`",
				"gitlabToken = \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_TOKEN = \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlabToken = glcbt-fakru_fakru057x78545lqtm5q",
				"{\n    \"gitlab_token\": \"glcbt-fakru_fakru057x78545lqtm5q\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glcbt-fakru_fakru057x78545lqtm5q\\nBACKUP_ENABLED=true\"}",
				"var gitlabToken string = \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"String gitlabToken = \"glcbt-fakru_fakru057x78545lqtm5q\";",
				"System.setProperty(\"GITLAB_TOKEN\", \"glcbt-fakru_fakru057x78545lqtm5q\")",
				"gitlab_TOKEN := \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_TOKEN ::= \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlab_token: glcbt-fakru_fakru057x78545lqtm5q",
				"gitlab_token: \"glcbt-fakru_fakru057x78545lqtm5q\"",
				"gitlabToken := \"glcbt-fakru_fakru057x78545lqtm5q\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitlabCiCdJobToken())
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
