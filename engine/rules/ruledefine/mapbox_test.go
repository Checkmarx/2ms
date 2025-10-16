package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapboxAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MapBox validation",
			truePositives: []string{
				"var mapboxToken = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken = 'pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5'",
				"mapbox_TOKEN = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapbox_TOKEN := \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"{\n    \"mapbox_token\": \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"\n}",
				"<mapboxToken>\n    pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\n</mapboxToken>",
				"mapbox_token: \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken := \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapbox_TOKEN ::= \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",

				"mapbox_TOKEN :::= \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapbox_TOKEN ?= \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken=\"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken=pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5",
				"mapboxToken = pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5",
				"var mapboxToken string = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapbox_token: pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5",
				"string mapboxToken = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\";",
				"$mapboxToken .= \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"mapboxToken = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"System.setProperty(\"MAPBOX_TOKEN\", \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\")",
				"  \"mapboxToken\" => \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\"",
				"{\"config.ini\": \"MAPBOX_TOKEN=pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\\nBACKUP_ENABLED=true\"}",
				"mapbox_token: 'pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5'",
				"mapboxToken := `pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5`",
				"String mapboxToken = \"pk.tm6inp1xohfcaylc6pfqk5r44z1xiz8l03g1tdvrlmb8ntia3aikkjmqru0n.tm6inp1xohfcaylc6pfqk5\";",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(MapBox())
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
