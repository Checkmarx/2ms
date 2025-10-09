package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkedinClientID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LinkedinClientID validation",
			truePositives: []string{

				"linkedinToken = y0bxbdu095sye6",
				"{\"config.ini\": \"LINKEDIN_TOKEN=y0bxbdu095sye6\\nBACKUP_ENABLED=true\"}",
				"linkedin_token: 'y0bxbdu095sye6'",
				"linkedin_token: \"y0bxbdu095sye6\"",
				"String linkedinToken = \"y0bxbdu095sye6\";",
				"linkedin_TOKEN := \"y0bxbdu095sye6\"",
				"linkedinToken=\"y0bxbdu095sye6\"",
				"var linkedinToken = \"y0bxbdu095sye6\"",
				"  \"linkedinToken\" => \"y0bxbdu095sye6\"",
				"linkedin_TOKEN ?= \"y0bxbdu095sye6\"",
				"linkedinToken = \"y0bxbdu095sye6\"",
				"linkedinToken=y0bxbdu095sye6",
				"{\n    \"linkedin_token\": \"y0bxbdu095sye6\"\n}",
				"<linkedinToken>\n    y0bxbdu095sye6\n</linkedinToken>",
				"linkedin_token: y0bxbdu095sye6",
				"string linkedinToken = \"y0bxbdu095sye6\";",
				"var linkedinToken string = \"y0bxbdu095sye6\"",
				"linkedinToken := `y0bxbdu095sye6`",
				"linkedinToken := \"y0bxbdu095sye6\"",
				"$linkedinToken .= \"y0bxbdu095sye6\"",
				"linkedinToken = 'y0bxbdu095sye6'",
				"linkedinToken = \"y0bxbdu095sye6\"",
				"System.setProperty(\"LINKEDIN_TOKEN\", \"y0bxbdu095sye6\")",
				"linkedin_TOKEN = \"y0bxbdu095sye6\"",
				"linkedin_TOKEN ::= \"y0bxbdu095sye6\"",
				"linkedin_TOKEN :::= \"y0bxbdu095sye6\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(LinkedinClientID())
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
