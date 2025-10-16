package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFastlyAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FastlyAPIToken validation",
			truePositives: []string{
				"fastlyToken = '5k9qr6t47si_e83jioh0u2v4m5d6nrv9'",
				"fastly_TOKEN := \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"{\n    \"fastly_token\": \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"\n}",
				"<fastlyToken>\n    5k9qr6t47si_e83jioh0u2v4m5d6nrv9\n</fastlyToken>",
				"fastly_token: '5k9qr6t47si_e83jioh0u2v4m5d6nrv9'",
				"System.setProperty(\"FASTLY_TOKEN\", \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\")",
				"  \"fastlyToken\" => \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastly_TOKEN ::= \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastly_token: \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"var fastlyToken string = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken := \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken := `5k9qr6t47si_e83jioh0u2v4m5d6nrv9`",
				"var fastlyToken = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastly_TOKEN = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastly_TOKEN ?= \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken=\"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"fastlyToken=5k9qr6t47si_e83jioh0u2v4m5d6nrv9",
				"fastlyToken = 5k9qr6t47si_e83jioh0u2v4m5d6nrv9",
				"string fastlyToken = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\";",
				"String fastlyToken = \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\";",
				"fastly_TOKEN :::= \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
				"{\"config.ini\": \"FASTLY_TOKEN=5k9qr6t47si_e83jioh0u2v4m5d6nrv9\\nBACKUP_ENABLED=true\"}",
				"fastly_token: 5k9qr6t47si_e83jioh0u2v4m5d6nrv9",
				"$fastlyToken .= \"5k9qr6t47si_e83jioh0u2v4m5d6nrv9\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FastlyAPIToken())
			d := createSingleRuleDetector(rule)

			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
