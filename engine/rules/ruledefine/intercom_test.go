package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntercomAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Intercom validation",
			truePositives: []string{
				"intercomToken=\"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercomToken = dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5",
				"intercom_token: dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5",
				"String intercomToken = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\";",
				"$intercomToken .= \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercomToken = 'dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5'",
				"  \"intercomToken\" => \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercomToken=dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5",
				"{\n    \"intercom_token\": \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"\n}",
				"intercomToken := `dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5`",
				"var intercomToken = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"System.setProperty(\"INTERCOM_TOKEN\", \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\")",
				"intercom_TOKEN := \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercomToken = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"{\"config.ini\": \"INTERCOM_TOKEN=dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\\nBACKUP_ENABLED=true\"}",
				"<intercomToken>\n    dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\n</intercomToken>",
				"intercom_token: 'dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5'",
				"intercom_token: \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"var intercomToken string = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercomToken := \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercom_TOKEN = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"string intercomToken = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\";",
				"intercomToken = \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercom_TOKEN ::= \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercom_TOKEN :::= \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
				"intercom_TOKEN ?= \"dsu2inbsugcpc6-yv7o_2hzdx71db6run5k_as7qtn71utex36e8ugso8dg5\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Intercom())
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
