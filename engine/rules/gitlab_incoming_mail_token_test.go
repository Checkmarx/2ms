package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabIncomingMailToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabIncomingMailToken validation",
			truePositives: []string{
				"String gitlabToken = \"glimt-ig7zd3czsddapn2o36n4c1zqy\";",
				"gitlab_TOKEN ::= \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"{\n    \"gitlab_token\": \"glimt-ig7zd3czsddapn2o36n4c1zqy\"\n}",
				"{\"config.ini\": \"GITLAB_TOKEN=glimt-ig7zd3czsddapn2o36n4c1zqy\\nBACKUP_ENABLED=true\"}",
				"<gitlabToken>\n    glimt-ig7zd3czsddapn2o36n4c1zqy\n</gitlabToken>",
				"gitlab_token: glimt-ig7zd3czsddapn2o36n4c1zqy",
				"gitlabToken := \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"  \"gitlabToken\" => \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlab_TOKEN := \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlabToken = \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlabToken=glimt-ig7zd3czsddapn2o36n4c1zqy",
				"gitlabToken = glimt-ig7zd3czsddapn2o36n4c1zqy",
				"var gitlabToken = \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"$gitlabToken .= \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlabToken = \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glimt-ig7zd3czsddapn2o36n4c1zqy\")",
				"gitlab_TOKEN = \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlab_token: 'glimt-ig7zd3czsddapn2o36n4c1zqy'",
				"gitlab_token: \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlabToken := `glimt-ig7zd3czsddapn2o36n4c1zqy`",
				"gitlabToken = 'glimt-ig7zd3czsddapn2o36n4c1zqy'",
				"gitlab_TOKEN :::= \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlab_TOKEN ?= \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"gitlabToken=\"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
				"string gitlabToken = \"glimt-ig7zd3czsddapn2o36n4c1zqy\";",
				"var gitlabToken string = \"glimt-ig7zd3czsddapn2o36n4c1zqy\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitlabIncomingMailToken())
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
