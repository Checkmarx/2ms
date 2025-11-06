package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthressServiceClientAccessKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Authress validation",
			truePositives: []string{
				"authress_TOKEN ::= \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authress_TOKEN ?= \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken = sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop",
				"authressToken := `sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop`",
				"var authressToken = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken = 'sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop'",
				"  \"authressToken\" => \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken=\"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken=sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop",
				"<authressToken>\n    sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\n</authressToken>",
				"authress_token: 'sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop'",
				"authress_token: \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"string authressToken = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\";",
				"var authressToken string = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"$authressToken .= \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authressToken = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"System.setProperty(\"AUTHRESS_TOKEN\", \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\")",
				"authress_TOKEN = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"authress_TOKEN :::= \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"{\n    \"authress_token\": \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"\n}",
				"{\"config.ini\": \"AUTHRESS_TOKEN=sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\\nBACKUP_ENABLED=true\"}",
				"authress_token: sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop",
				"authressToken := \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
				"String authressToken = \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\";",
				"authress_TOKEN := \"sc_i7z3km4wuf.tx6m.acc_6hwnkejm5d.x7f2nx64-cepuqmzzce799-f8xxjfia7vur7xyop\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Authress())
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
