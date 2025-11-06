package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabOauthAppSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TestGitlabOauthAppSecret validation",
			truePositives: []string{
				"String gitlabToken = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\";",
				"gitlabToken = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"  \"gitlabToken\" => \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_TOKEN := \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlabToken=\"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlabToken = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_token: gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9",
				"gitlab_token: 'gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9'",
				"gitlabToken := \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"$gitlabToken .= \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_TOKEN :::= \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"<gitlabToken>\n    gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\n</gitlabToken>",
				"var gitlabToken string = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"var gitlabToken = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_TOKEN = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_TOKEN ::= \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"gitlab_TOKEN ?= \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
				"{\n    \"gitlab_token\": \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"\n}",
				"string gitlabToken = \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\";",
				"gitlabToken := `gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9`",
				"gitlabToken = 'gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9'",
				"System.setProperty(\"GITLAB_TOKEN\", \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\")",
				"gitlabToken=gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9",
				"gitlabToken = gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9",
				"{\"config.ini\": \"GITLAB_TOKEN=gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: \"gloas-a4h74ta0y433xn8e9xwowsckc7nnn5f7fj61vcpui6iudxkqv7r4g8pes37ph8g9\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitlabOauthAppSecret())
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
