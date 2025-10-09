package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSnyk(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Snyk validation",
			truePositives: []string{
				"snykToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snykToken = 12345678-ABCD-ABCD-ABCD-1234567890AB",
				"<snykToken>\n    12345678-ABCD-ABCD-ABCD-1234567890AB\n</snykToken>",
				"string snykToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\";",
				"snykToken := \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snykToken = '12345678-ABCD-ABCD-ABCD-1234567890AB'",
				"snykToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snyk_TOKEN :::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"{\n    \"snyk_token\": \"12345678-ABCD-ABCD-ABCD-1234567890AB\"\n}",
				"snyk_token: 12345678-ABCD-ABCD-ABCD-1234567890AB",
				"snyk_token: '12345678-ABCD-ABCD-ABCD-1234567890AB'",
				"snyk_TOKEN ?= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snykToken=12345678-ABCD-ABCD-ABCD-1234567890AB",
				"{\"config.ini\": \"SNYK_TOKEN=12345678-ABCD-ABCD-ABCD-1234567890AB\\nBACKUP_ENABLED=true\"}",
				"snyk_token: \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snykToken := `12345678-ABCD-ABCD-ABCD-1234567890AB`",
				"String snykToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\";",
				"$snykToken .= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"System.setProperty(\"SNYK_TOKEN\", \"12345678-ABCD-ABCD-ABCD-1234567890AB\")",
				"  \"snykToken\" => \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snykToken=\"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"var snykToken string = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"var snykToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snyk_TOKEN = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snyk_TOKEN := \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"snyk_TOKEN ::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"const SNYK_TOKEN = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"const SNYK_KEY = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_TOKEN := \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_TOKEN ::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_TOKEN :::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_TOKEN ?= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_API_KEY ?= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_API_TOKEN = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"SNYK_OAUTH_TOKEN = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(Snyk())
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
