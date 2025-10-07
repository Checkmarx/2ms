package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigitaloceanRefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DigitalOceanRefreshToken validation",
			truePositives: []string{
				"do_token: dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044",
				"do_token: 'dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044'",

				"$doToken .= \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken = 'dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044'",

				"  \"doToken\" => \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"do_TOKEN = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"do_token: \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"string doToken = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\";",
				"do_TOKEN ::= \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken=\"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken = dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044",
				"{\n    \"do_token\": \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"\n}",
				"var doToken string = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"var doToken = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"System.setProperty(\"DO_TOKEN\", \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\")",
				"do_TOKEN :::= \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"<doToken>\n    dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\n</doToken>",
				"doToken := \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken := `dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044`",
				"String doToken = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\";",
				"doToken = \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"do_TOKEN := \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"do_TOKEN ?= \"dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\"",
				"doToken=dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044",
				"{\"config.ini\": \"DO_TOKEN=dor_v1_8bba6aaa279c1df537dc233bb72b615b6a1fb5267126661e8d775d87f95f2044\\nBACKUP_ENABLED=true\"}",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(DigitalOceanRefreshToken())
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
