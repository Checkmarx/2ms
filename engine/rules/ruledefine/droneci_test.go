package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDroneciAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DroneciAccessToken validation",
			truePositives: []string{
				"var droneciToken = \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"$droneciToken .= \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"System.setProperty(\"DRONECI_TOKEN\", \"z0fursjdrucdemvclz7foi69ywcmpytq\")",
				"droneci_TOKEN ?= \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken = z0fursjdrucdemvclz7foi69ywcmpytq",
				"droneci_token: 'z0fursjdrucdemvclz7foi69ywcmpytq'",
				"droneci_token: \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"string droneciToken = \"z0fursjdrucdemvclz7foi69ywcmpytq\";",
				"droneciToken := \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneci_TOKEN = \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneci_TOKEN := \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken=z0fursjdrucdemvclz7foi69ywcmpytq",
				"{\n    \"droneci_token\": \"z0fursjdrucdemvclz7foi69ywcmpytq\"\n}",
				"<droneciToken>\n    z0fursjdrucdemvclz7foi69ywcmpytq\n</droneciToken>",
				"var droneciToken string = \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken = \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneci_TOKEN ::= \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken = \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"{\"config.ini\": \"DRONECI_TOKEN=z0fursjdrucdemvclz7foi69ywcmpytq\\nBACKUP_ENABLED=true\"}",
				"droneci_token: z0fursjdrucdemvclz7foi69ywcmpytq",
				"String droneciToken = \"z0fursjdrucdemvclz7foi69ywcmpytq\";",
				"droneciToken = 'z0fursjdrucdemvclz7foi69ywcmpytq'",
				"  \"droneciToken\" => \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneci_TOKEN :::= \"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken=\"z0fursjdrucdemvclz7foi69ywcmpytq\"",
				"droneciToken := `z0fursjdrucdemvclz7foi69ywcmpytq`",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(DroneciAccessToken())
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
