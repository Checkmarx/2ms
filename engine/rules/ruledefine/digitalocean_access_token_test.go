package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigitalOceanOAuthToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DigitalOceanOAuthToken validation",
			truePositives: []string{
				"<doToken>\n    doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\n</doToken>",
				"do_token: doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd",
				"var doToken string = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"String doToken = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\";",
				"do_TOKEN := \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"do_TOKEN ::= \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"do_TOKEN ?= \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"doToken=doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd",
				"doToken = doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd",
				"do_token: 'doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd'",
				"doToken := \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"var doToken = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"$doToken .= \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"doToken = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"System.setProperty(\"DO_TOKEN\", \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\")",
				"doToken=\"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",

				"{\"config.ini\": \"DO_TOKEN=doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\\nBACKUP_ENABLED=true\"}",
				"do_token: \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"doToken := `doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd`",
				"do_TOKEN = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"do_TOKEN :::= \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"doToken = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
				"{\n    \"do_token\": \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"\n}",
				"string doToken = \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\";",
				"doToken = 'doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd'",
				"  \"doToken\" => \"doo_v1_ad468cec672dfdd406808a31faa39493a96075c0276372adf619ac643e66d8cd\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(DigitalOceanOAuthToken())
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
