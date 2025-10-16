package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendGridAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SendGridAPIToken validation",
			truePositives: []string{
				"  \"sengridAPITokenToken\" => \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPIToken_TOKEN = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPIToken_TOKEN := \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken=SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d",
				"sengridAPITokenToken = SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d",
				"{\n    \"sengridAPIToken_token\": \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"\n}",
				"<sengridAPITokenToken>\n    SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\n</sengridAPITokenToken>",
				"sengridAPIToken_token: SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d",
				"var sengridAPITokenToken string = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken := \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"$sengridAPITokenToken .= \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken := `SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d`",
				"String sengridAPITokenToken = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\";",
				"sengridAPITokenToken = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"System.setProperty(\"SENGRIDAPITOKEN_TOKEN\", \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\")",
				"sengridAPIToken_TOKEN ::= \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPIToken_TOKEN :::= \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPIToken_token: 'SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d'",
				"string sengridAPITokenToken = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\";",
				"var sengridAPITokenToken = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPIToken_TOKEN ?= \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken=\"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken = \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"{\"config.ini\": \"SENGRIDAPITOKEN_TOKEN=SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\\nBACKUP_ENABLED=true\"}",
				"sengridAPIToken_token: \"SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d\"",
				"sengridAPITokenToken = 'SG._xxgmrv80c_d=gqno05eb1njivvb=y3my-ft=n2kss6xdw2llkmq_7zvyas0jg7o1d'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SendGridAPIToken())
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
