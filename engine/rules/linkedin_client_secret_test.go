package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkedinClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LinkedinClientSecret validation",
			truePositives: []string{
				"String linkedinToken = \"3653php6v8chmlsm\";",
				"System.setProperty(\"LINKEDIN_TOKEN\", \"3653php6v8chmlsm\")",
				"linkedin_TOKEN = \"3653php6v8chmlsm\"",
				"linkedin_TOKEN := \"3653php6v8chmlsm\"",
				"linkedinToken=\"3653php6v8chmlsm\"",
				"string linkedinToken = \"3653php6v8chmlsm\";",
				"var linkedinToken string = \"3653php6v8chmlsm\"",
				"linkedinToken = \"3653php6v8chmlsm\"",
				"  \"linkedinToken\" => \"3653php6v8chmlsm\"",
				"linkedin_TOKEN :::= \"3653php6v8chmlsm\"",
				"linkedinToken = \"3653php6v8chmlsm\"",
				"{\n    \"linkedin_token\": \"3653php6v8chmlsm\"\n}",
				"linkedin_token: 3653php6v8chmlsm",
				"linkedinToken := \"3653php6v8chmlsm\"",
				"var linkedinToken = \"3653php6v8chmlsm\"",
				"linkedinToken = 3653php6v8chmlsm",
				"{\"config.ini\": \"LINKEDIN_TOKEN=3653php6v8chmlsm\\nBACKUP_ENABLED=true\"}",
				"<linkedinToken>\n    3653php6v8chmlsm\n</linkedinToken>",
				"linkedin_token: \"3653php6v8chmlsm\"",
				"$linkedinToken .= \"3653php6v8chmlsm\"",
				"linkedinToken = '3653php6v8chmlsm'",
				"linkedin_TOKEN ::= \"3653php6v8chmlsm\"",
				"linkedin_TOKEN ?= \"3653php6v8chmlsm\"",
				"linkedinToken=3653php6v8chmlsm",
				"linkedin_token: '3653php6v8chmlsm'",
				"linkedinToken := `3653php6v8chmlsm`",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(LinkedinClientSecret())
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
