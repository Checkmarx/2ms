package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSquareSpaceAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SquareSpaceAccessToken validation",
			truePositives: []string{
				"squarespace_TOKEN ?= \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespaceToken=c5a720ae-aafa-0064-628a-d7b7db2cc2ce",
				"{\n    \"squarespace_token\": \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"\n}",
				"squarespace_token: 'c5a720ae-aafa-0064-628a-d7b7db2cc2ce'",
				"$squarespaceToken .= \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespaceToken = 'c5a720ae-aafa-0064-628a-d7b7db2cc2ce'",
				"squarespaceToken = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"<squarespaceToken>\n    c5a720ae-aafa-0064-628a-d7b7db2cc2ce\n</squarespaceToken>",
				"squarespace_token: c5a720ae-aafa-0064-628a-d7b7db2cc2ce",
				"var squarespaceToken string = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespaceToken := `c5a720ae-aafa-0064-628a-d7b7db2cc2ce`",
				"squarespaceToken=\"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespace_token: \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"string squarespaceToken = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\";",
				"squarespaceToken := \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"String squarespaceToken = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\";",
				"squarespaceToken = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"  \"squarespaceToken\" => \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespace_TOKEN = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespaceToken = c5a720ae-aafa-0064-628a-d7b7db2cc2ce",
				"{\"config.ini\": \"SQUARESPACE_TOKEN=c5a720ae-aafa-0064-628a-d7b7db2cc2ce\\nBACKUP_ENABLED=true\"}",
				"var squarespaceToken = \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"System.setProperty(\"SQUARESPACE_TOKEN\", \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\")",
				"squarespace_TOKEN := \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespace_TOKEN ::= \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
				"squarespace_TOKEN :::= \"c5a720ae-aafa-0064-628a-d7b7db2cc2ce\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SquareSpaceAccessToken())
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
