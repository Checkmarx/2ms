package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigitalOceanPat(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DigitalOceanPAT validation",
			truePositives: []string{
				"do_token: dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480",
				"doToken = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"  \"doToken\" => \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"do_TOKEN := \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"do_TOKEN ?= \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"{\n    \"do_token\": \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"\n}",
				"do_token: \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"doToken := `dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480`",
				"doToken = 'dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480'",
				"doToken = dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480",
				"{\"config.ini\": \"DO_TOKEN=dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\\nBACKUP_ENABLED=true\"}",
				"<doToken>\n    dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\n</doToken>",
				"do_token: 'dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480'",
				"string doToken = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\";",
				"var doToken string = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"String doToken = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\";",
				"do_TOKEN ::= \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"doToken=\"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"doToken=dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480",
				"doToken := \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"var doToken = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"$doToken .= \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"System.setProperty(\"DO_TOKEN\", \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\")",
				"do_TOKEN = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"do_TOKEN :::= \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
				"doToken = \"dop_v1_8b2952adf472fd7273538c1c15bfe8ab23e9ac876ad83b324165302e04f3e480\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(DigitalOceanPAT())
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
