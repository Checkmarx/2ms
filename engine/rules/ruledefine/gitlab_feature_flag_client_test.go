package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabFeatureFlagClientToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabDeployToken validation",
			truePositives: []string{
				"gitlab_token: glffct-5c00opi1xi9i2hcm68x6",
				"gitlabToken := \"glffct-5c00opi1xi9i2hcm68x6\"",
				"$gitlabToken .= \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlabToken = 'glffct-5c00opi1xi9i2hcm68x6'",
				"gitlabToken = \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlab_TOKEN := \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlabToken = \"glffct-5c00opi1xi9i2hcm68x6\"",
				"{\"config.ini\": \"GITLAB_TOKEN=glffct-5c00opi1xi9i2hcm68x6\\nBACKUP_ENABLED=true\"}",
				"gitlabToken := `glffct-5c00opi1xi9i2hcm68x6`",
				"String gitlabToken = \"glffct-5c00opi1xi9i2hcm68x6\";",
				"System.setProperty(\"GITLAB_TOKEN\", \"glffct-5c00opi1xi9i2hcm68x6\")",
				"  \"gitlabToken\" => \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlab_TOKEN ?= \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlabToken=\"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlabToken=glffct-5c00opi1xi9i2hcm68x6",
				"gitlabToken = glffct-5c00opi1xi9i2hcm68x6",
				"string gitlabToken = \"glffct-5c00opi1xi9i2hcm68x6\";",
				"var gitlabToken = \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlab_TOKEN = \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlab_TOKEN :::= \"glffct-5c00opi1xi9i2hcm68x6\"",
				"{\n    \"gitlab_token\": \"glffct-5c00opi1xi9i2hcm68x6\"\n}",
				"<gitlabToken>\n    glffct-5c00opi1xi9i2hcm68x6\n</gitlabToken>",
				"gitlab_token: 'glffct-5c00opi1xi9i2hcm68x6'",
				"gitlab_token: \"glffct-5c00opi1xi9i2hcm68x6\"",
				"var gitlabToken string = \"glffct-5c00opi1xi9i2hcm68x6\"",
				"gitlab_TOKEN ::= \"glffct-5c00opi1xi9i2hcm68x6\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitlabFeatureFlagClientToken())
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
