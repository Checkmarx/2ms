package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNpmAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NPM validation",
			truePositives: []string{
				"string npmAccessTokenToken = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\";",
				"npmAccessTokenToken := `npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3`",
				"System.setProperty(\"NPMACCESSTOKEN_TOKEN\", \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\")",
				"  \"npmAccessTokenToken\" => \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessTokenToken=\"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessTokenToken = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"var npmAccessTokenToken string = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessToken_TOKEN := \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessToken_TOKEN ::= \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessToken_TOKEN :::= \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessTokenToken=npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3",
				"npmAccessTokenToken = npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3",
				"String npmAccessTokenToken = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\";",
				"npmAccessToken_TOKEN = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"<npmAccessTokenToken>\n    npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\n</npmAccessTokenToken>",
				"npmAccessToken_token: \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessTokenToken := \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"var npmAccessTokenToken = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"$npmAccessTokenToken .= \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessTokenToken = 'npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3'",
				"npmAccessTokenToken = \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"npmAccessToken_TOKEN ?= \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"",
				"{\n    \"npmAccessToken_token\": \"npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\"\n}",
				"{\"config.ini\": \"NPMACCESSTOKEN_TOKEN=npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3\\nBACKUP_ENABLED=true\"}",

				"npmAccessToken_token: npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3",
				"npmAccessToken_token: 'npm_o8y1twtprpmrouumu3elbgmwp2342lu7t4f3'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NPM())
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
