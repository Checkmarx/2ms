package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitlabPat(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitlabPat validation",
			truePositives: []string{
				"{\n    \"gitlab_token\": \"glpat-ujkk226tkqcxwmh838id\"\n}",
				"<gitlabToken>\n    glpat-ujkk226tkqcxwmh838id\n</gitlabToken>",
				"$gitlabToken .= \"glpat-ujkk226tkqcxwmh838id\"",
				"System.setProperty(\"GITLAB_TOKEN\", \"glpat-ujkk226tkqcxwmh838id\")",
				"gitlabToken=glpat-ujkk226tkqcxwmh838id",
				"gitlabToken = glpat-ujkk226tkqcxwmh838id",
				"{\"config.ini\": \"GITLAB_TOKEN=glpat-ujkk226tkqcxwmh838id\\nBACKUP_ENABLED=true\"}",
				"gitlab_token: glpat-ujkk226tkqcxwmh838id",
				"string gitlabToken = \"glpat-ujkk226tkqcxwmh838id\";",
				"var gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN :::= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_token: \"glpat-ujkk226tkqcxwmh838id\"",
				"var gitlabToken string = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken := \"glpat-ujkk226tkqcxwmh838id\"",
				"String gitlabToken = \"glpat-ujkk226tkqcxwmh838id\";",
				"gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN := \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN ?= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_token: 'glpat-ujkk226tkqcxwmh838id'",
				"gitlabToken := `glpat-ujkk226tkqcxwmh838id`",
				"gitlabToken = 'glpat-ujkk226tkqcxwmh838id'",
				"  \"gitlabToken\" => \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlab_TOKEN ::= \"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken=\"glpat-ujkk226tkqcxwmh838id\"",
				"gitlabToken = \"glpat-ujkk226tkqcxwmh838id\"",
			},
			falsePositives: []string{
				"glpat-XXXXXXXXXXX-XXXXXXXX",
				// longer than 20 chars after the prefix: not a legacy PAT (routable tokens are covered by Gitlab-Pat-Routable)
				"glpat-0thvkg8tnsqpnek96k0pa3latn9.01.0t0thvkg8",
				"glpat-D0agd3p5LcvzA5U_Udl-abcdefg.01.0t0thvkg8",
				"glpat-D0agd3p5LcvzA5U_Udl-abcdefg",
				// a legacy-length token directly followed by more token characters is not a legacy PAT
				"glpat-sKkgxjBs2KBpGA6Ad0TH_prod",
				"glpat-sKkgxjBs2KBpGA6Ad0TH-prod",
				"glpat-sKkgxjBs2KBpGA6Ad0THprod",
				// malformed routable tokens (invalid version/suffix segments) are not reported as Gitlab-Pat
				"glpat-fpThoJpoAEoVo28MA9C0sJ55appdMkF9h8glRQTV2Mf.011.ni134dx4u;",
				"glpat-2qXmt4wRrfcZp9NoCKKmTJfXmYqIkwGzKAmmUOg8iuI.1.q6uhzx3g1;",
				"glpat-CyAmXNMrlFRgNYu7qK0ZMBuviX6lisA2U9A83PxKRbZ.0A.mnm7r0490;",
				"glpat-tqsZLIVhDA4lmFUYcOD4YfERaKKF2laboiJfavZ8WKO.01.xosbk5z7;",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GitlabPat())
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
