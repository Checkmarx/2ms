package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsanaClientId(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "AsanaClientID validation",
			truePositives: []string{
				"asanaToken=\"1309455782606278\"",
				"asanaToken=1309455782606278",
				"{\n    \"asana_token\": \"1309455782606278\"\n}",
				"asanaToken := \"1309455782606278\"",
				"asanaToken = '1309455782606278'",
				"  \"asanaToken\" => \"1309455782606278\"",
				"asana_TOKEN = \"1309455782606278\"",
				"asana_TOKEN := \"1309455782606278\"",
				"asanaToken = \"1309455782606278\"",
				"asana_token: '1309455782606278'",
				"asana_token: \"1309455782606278\"",
				"String asanaToken = \"1309455782606278\";",
				"var asanaToken = \"1309455782606278\"",
				"asanaToken = \"1309455782606278\"",
				"{\"config.ini\": \"ASANA_TOKEN=1309455782606278\\nBACKUP_ENABLED=true\"}",
				"asanaToken := `1309455782606278`",
				"$asanaToken .= \"1309455782606278\"",
				"System.setProperty(\"ASANA_TOKEN\", \"1309455782606278\")",
				"asana_TOKEN :::= \"1309455782606278\"",
				"asanaToken = 1309455782606278",
				"<asanaToken>\n    1309455782606278\n</asanaToken>",
				"asana_token: 1309455782606278",
				"string asanaToken = \"1309455782606278\";",
				"var asanaToken string = \"1309455782606278\"",
				"asana_TOKEN ::= \"1309455782606278\"",
				"asana_TOKEN ?= \"1309455782606278\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AsanaClientID())
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
