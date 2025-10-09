package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabFeedToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabDeployToken validation",
			truePositives: []string{
				"{\n    \"gitlab_token\": \"glft-cu209ano98ptb1bbzacf\"\n}",
				"gitlab_token: 'glft-cu209ano98ptb1bbzacf'",
				"  \"gitlabToken\" => \"glft-cu209ano98ptb1bbzacf\"",
				"gitlab_TOKEN ?= \"glft-cu209ano98ptb1bbzacf\"",
				"string gitlabToken = \"glft-cu209ano98ptb1bbzacf\";",
				"var gitlabToken string = \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken := \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken := `glft-cu209ano98ptb1bbzacf`",
				"String gitlabToken = \"glft-cu209ano98ptb1bbzacf\";",
				"$gitlabToken .= \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken = 'glft-cu209ano98ptb1bbzacf'",
				"gitlabToken = \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken=\"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken = \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken = glft-cu209ano98ptb1bbzacf",
				"gitlab_token: \"glft-cu209ano98ptb1bbzacf\"",
				"var gitlabToken = \"glft-cu209ano98ptb1bbzacf\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glft-cu209ano98ptb1bbzacf\")",
				"gitlab_TOKEN = \"glft-cu209ano98ptb1bbzacf\"",
				"gitlab_TOKEN ::= \"glft-cu209ano98ptb1bbzacf\"",
				"gitlabToken=glft-cu209ano98ptb1bbzacf",
				"{\"config.ini\": \"GITLAB_TOKEN=glft-cu209ano98ptb1bbzacf\\nBACKUP_ENABLED=true\"}",
				"<gitlabToken>\n    glft-cu209ano98ptb1bbzacf\n</gitlabToken>",
				"gitlab_token: glft-cu209ano98ptb1bbzacf",
				"gitlab_TOKEN := \"glft-cu209ano98ptb1bbzacf\"",
				"gitlab_TOKEN :::= \"glft-cu209ano98ptb1bbzacf\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabFeedToken())
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
