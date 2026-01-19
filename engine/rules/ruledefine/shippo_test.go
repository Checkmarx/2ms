package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShippoAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ShippoAPIToken validation",
			truePositives: []string{
				"shippo_TOKEN := \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"{\n    \"shippo_token\": \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"\n}",
				"var shippoToken string = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken := `shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9`",
				"System.setProperty(\"SHIPPO_TOKEN\", \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\")",
				"  \"shippoToken\" => \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippo_TOKEN = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippo_TOKEN ::= \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippo_TOKEN :::= \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken=\"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken = shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9",
				"{\"config.ini\": \"SHIPPO_TOKEN=shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\\nBACKUP_ENABLED=true\"}",
				"string shippoToken = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\";",
				"shippoToken := \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"$shippoToken .= \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippo_token: shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9",
				"shippo_token: 'shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9'",
				"shippo_token: \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken = 'shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9'",
				"shippo_TOKEN ?= \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken=shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9",
				"<shippoToken>\n    shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\n</shippoToken>",
				"String shippoToken = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\";",
				"var shippoToken = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken = \"shippo_live_f05d9f6676b6d1576dfb10acf04145359907e0f9\"",
				"shippoToken = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"<shippoToken>\n    shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\n</shippoToken>",
				"shippo_token: 'shippo_test_bd481ce4664653efca749c8692b795b2cf57b207'",
				"$shippoToken .= \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"  \"shippoToken\" => \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippo_TOKEN = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippo_TOKEN ::= \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippo_TOKEN :::= \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippoToken=shippo_test_bd481ce4664653efca749c8692b795b2cf57b207",
				"{\n    \"shippo_token\": \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"\n}",
				"shippo_token: \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"string shippoToken = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\";",
				"shippoToken := \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippoToken = 'shippo_test_bd481ce4664653efca749c8692b795b2cf57b207'",
				"shippo_TOKEN := \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippo_token: shippo_test_bd481ce4664653efca749c8692b795b2cf57b207",
				"var shippoToken string = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippoToken := `shippo_test_bd481ce4664653efca749c8692b795b2cf57b207`",
				"var shippoToken = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippoToken=\"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"shippoToken = shippo_test_bd481ce4664653efca749c8692b795b2cf57b207",
				"{\"config.ini\": \"SHIPPO_TOKEN=shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\\nBACKUP_ENABLED=true\"}",
				"String shippoToken = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\";",
				"shippoToken = \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
				"System.setProperty(\"SHIPPO_TOKEN\", \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\")",
				"shippo_TOKEN ?= \"shippo_test_bd481ce4664653efca749c8692b795b2cf57b207\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(ShippoAPIToken())
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
