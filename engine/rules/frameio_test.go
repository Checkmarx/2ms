package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrameioAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FrameIO validation",
			truePositives: []string{
				"frameio_TOKEN = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameio_TOKEN := \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameio_TOKEN :::= \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameioToken = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"{\"config.ini\": \"FRAMEIO_TOKEN=fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\\nBACKUP_ENABLED=true\"}",
				"<frameioToken>\n    fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\n</frameioToken>",
				"frameio_token: \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"var frameioToken = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameioToken = 'fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2'",
				"frameioToken = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameio_TOKEN ::= \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameioToken=fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2",
				"frameio_token: fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2",
				"frameioToken := \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"$frameioToken .= \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"  \"frameioToken\" => \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameioToken=\"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameio_token: 'fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2'",
				"frameioToken := `fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2`",
				"String frameioToken = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\";",

				"frameio_TOKEN ?= \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"frameioToken = fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2",
				"{\n    \"frameio_token\": \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"\n}",
				"string frameioToken = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\";",
				"var frameioToken string = \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\"",
				"System.setProperty(\"FRAMEIO_TOKEN\", \"fio-u-u8n=6krboppcw02xyrs929u5phck=tso8o=ld=w9mnb3q_xf2gw2sact995m2j=2\")",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(FrameIO())
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
