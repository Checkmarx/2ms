package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabRunnerRegistrationToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabRunnerRegistrationToken validation",
			truePositives: []string{
				"gitlabToken = \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlabToken = GR1348941eqwy0ekoj35om2uq9u5w",
				"{\"config.ini\": \"GITLAB_TOKEN=GR1348941eqwy0ekoj35om2uq9u5w\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: GR1348941eqwy0ekoj35om2uq9u5w",
				"string gitlabToken = \"GR1348941eqwy0ekoj35om2uq9u5w\";",
				"var gitlabToken string = \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlabToken := \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"$gitlabToken .= \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlabToken=\"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"String gitlabToken = \"GR1348941eqwy0ekoj35om2uq9u5w\";",
				"gitlabToken = 'GR1348941eqwy0ekoj35om2uq9u5w'",
				"gitlabToken = \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"GR1348941eqwy0ekoj35om2uq9u5w\")",
				"gitlab_TOKEN := \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlab_TOKEN :::= \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlab_TOKEN ?= \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlabToken=GR1348941eqwy0ekoj35om2uq9u5w",
				"gitlab_token: 'GR1348941eqwy0ekoj35om2uq9u5w'",
				"gitlab_token: \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlabToken := `GR1348941eqwy0ekoj35om2uq9u5w`",
				"  \"gitlabToken\" => \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlab_TOKEN ::= \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"{\n    \"gitlab_token\": \"GR1348941eqwy0ekoj35om2uq9u5w\"\n}",
				"<gitlabToken>\n    GR1348941eqwy0ekoj35om2uq9u5w\n</gitlabToken>",
				"var gitlabToken = \"GR1348941eqwy0ekoj35om2uq9u5w\"",
				"gitlab_TOKEN = \"GR1348941eqwy0ekoj35om2uq9u5w\"",
			},
			falsePositives: []string{
				"GR134894112312312312312312312",
				"GR1348941XXXXXXXXXXXXXXXXXXXX",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabRunnerRegistrationToken())
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
