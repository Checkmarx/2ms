package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMattermostAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MattermostAccessToken validation",
			truePositives: []string{
				"mattermostToken=fjlof7vquijofaqnciyfoxjgey",
				"mattermost_token: fjlof7vquijofaqnciyfoxjgey",
				"mattermostToken := \"fjlof7vquijofaqnciyfoxjgey\"",
				"String mattermostToken = \"fjlof7vquijofaqnciyfoxjgey\";",
				"System.setProperty(\"MATTERMOST_TOKEN\", \"fjlof7vquijofaqnciyfoxjgey\")",
				"mattermost_TOKEN = \"fjlof7vquijofaqnciyfoxjgey\"",
				"<mattermostToken>\n    fjlof7vquijofaqnciyfoxjgey\n</mattermostToken>",
				"mattermost_token: 'fjlof7vquijofaqnciyfoxjgey'",
				"mattermostToken = 'fjlof7vquijofaqnciyfoxjgey'",
				"  \"mattermostToken\" => \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermost_TOKEN := \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermost_TOKEN ?= \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermostToken = fjlof7vquijofaqnciyfoxjgey",
				"{\n    \"mattermost_token\": \"fjlof7vquijofaqnciyfoxjgey\"\n}",
				"var mattermostToken string = \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermostToken := `fjlof7vquijofaqnciyfoxjgey`",
				"mattermost_TOKEN ::= \"fjlof7vquijofaqnciyfoxjgey\"",
				"{\"config.ini\": \"MATTERMOST_TOKEN=fjlof7vquijofaqnciyfoxjgey\\nBACKUP_ENABLED=true\"}",
				"mattermost_token: \"fjlof7vquijofaqnciyfoxjgey\"",
				"string mattermostToken = \"fjlof7vquijofaqnciyfoxjgey\";",
				"var mattermostToken = \"fjlof7vquijofaqnciyfoxjgey\"",
				"$mattermostToken .= \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermostToken = \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermost_TOKEN :::= \"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermostToken=\"fjlof7vquijofaqnciyfoxjgey\"",
				"mattermostToken = \"fjlof7vquijofaqnciyfoxjgey\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(MattermostAccessToken())
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
