package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefinedNetworkingApiToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DefinedNetworkingAPIToken validation",
			truePositives: []string{
				"dnkey_TOKEN ::= \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkey_TOKEN :::= \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkey_TOKEN ?= \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"{\"config.ini\": \"DNKEY_TOKEN=dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\\nBACKUP_ENABLED=true\"}",
				"dnkey_token: \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkeyToken = 'dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb'",
				"  \"dnkeyToken\" => \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkey_TOKEN = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkeyToken = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkeyToken=dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb",
				"dnkeyToken = dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb",
				"{\n    \"dnkey_token\": \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"\n}",
				"dnkey_token: dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb",
				"dnkey_token: 'dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb'",
				"dnkeyToken := `dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb`",
				"$dnkeyToken .= \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkeyToken=\"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"<dnkeyToken>\n    dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\n</dnkeyToken>",
				"string dnkeyToken = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\";",
				"var dnkeyToken string = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"String dnkeyToken = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\";",
				"var dnkeyToken = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkeyToken = \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"System.setProperty(\"DNKEY_TOKEN\", \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\")",
				"dnkeyToken := \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
				"dnkey_TOKEN := \"dnkey-5ae44c7musw8f70owbulcot0rr-5ae44c7musw8f70owbulcot0rrq1v=ysmx4owp0vno=y488v2qeb\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(DefinedNetworkingAPIToken())
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
