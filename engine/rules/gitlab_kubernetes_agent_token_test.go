package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabKubernetesAgentToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabKubernetesAgentToken validation",
			truePositives: []string{
				"gitlab_TOKEN ?= \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"<gitlabToken>\n    glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\n</gitlabToken>",
				"gitlab_token: glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813",
				"gitlabToken = 'glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813'",
				"gitlab_TOKEN = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlab_TOKEN ::= \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken=glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813",
				"gitlabToken = glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813",
				"{\n    \"gitlab_token\": \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\\nBACKUP_ENABLED=true\"}",
				"System.setProperty(\"GITLAB_TOKEN\", \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\")",
				"gitlab_TOKEN := \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlab_TOKEN :::= \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlab_token: 'glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813'",
				"string gitlabToken = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\";",
				"var gitlabToken string = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"String gitlabToken = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\";",
				"var gitlabToken = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"$gitlabToken .= \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken = \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken=\"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlab_token: \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken := \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
				"gitlabToken := `glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813`",
				"  \"gitlabToken\" => \"glagent-5v1jtvb921unznqpv3ux2fwj9poinplskgnd1djp7h5bp10813\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabKubernetesAgentToken())
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
