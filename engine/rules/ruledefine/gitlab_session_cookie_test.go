package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabSessionCookie(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabSessionCookie validation",
			truePositives: []string{
				"{\"config.ini\": \"GITLAB_TOKEN=_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: '_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8'",
				"gitlab_token: \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"string gitlabToken = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\";",
				"gitlabToken := \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"String gitlabToken = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\";",
				"var gitlabToken = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken = _gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8",
				"<gitlabToken>\n    _gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\n</gitlabToken>",
				"$gitlabToken .= \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"  \"gitlabToken\" => \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlab_TOKEN ?= \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken=\"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken = '_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8'",
				"gitlabToken = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlab_TOKEN ::= \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlab_TOKEN :::= \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken=_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8",
				"{\n    \"gitlab_token\": \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"\n}",
				"gitlab_token: _gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8",
				"var gitlabToken string = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken := `_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8`",
				"System.setProperty(\"GITLAB_TOKEN\", \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\")",
				"gitlab_TOKEN = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlab_TOKEN := \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
				"gitlabToken = \"_gitlab_session=8znqxile31v2vbi1obux74d7ijwhflk8\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitlabSessionCookie())
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
