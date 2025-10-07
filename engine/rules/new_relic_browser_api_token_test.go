package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRelicBrowserAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NewRelicBrowserAPIKey validation",
			truePositives: []string{
				"new-relicToken = NRJS-8a4d6f6eee8929a40ac",
				"var new-relicToken string = \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken := \"NRJS-8a4d6f6eee8929a40ac\"",
				"String new-relicToken = \"NRJS-8a4d6f6eee8929a40ac\";",
				"var new-relicToken = \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken = \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relic_TOKEN :::= \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relic_TOKEN ?= \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken=NRJS-8a4d6f6eee8929a40ac",
				"new-relic_token: \"NRJS-8a4d6f6eee8929a40ac\"",
				"$new-relicToken .= \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken = 'NRJS-8a4d6f6eee8929a40ac'",
				"  \"new-relicToken\" => \"NRJS-8a4d6f6eee8929a40ac\"",
				"<new-relicToken>\n    NRJS-8a4d6f6eee8929a40ac\n</new-relicToken>",
				"new-relic_token: 'NRJS-8a4d6f6eee8929a40ac'",
				"System.setProperty(\"NEW-RELIC_TOKEN\", \"NRJS-8a4d6f6eee8929a40ac\")",
				"new-relic_TOKEN := \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relic_TOKEN ::= \"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken=\"NRJS-8a4d6f6eee8929a40ac\"",
				"new-relicToken = \"NRJS-8a4d6f6eee8929a40ac\"",
				"{\n    \"new-relic_token\": \"NRJS-8a4d6f6eee8929a40ac\"\n}",
				"{\"config.ini\": \"NEW-RELIC_TOKEN=NRJS-8a4d6f6eee8929a40ac\\nBACKUP_ENABLED=true\"}",
				"new-relic_token: NRJS-8a4d6f6eee8929a40ac",
				"string new-relicToken = \"NRJS-8a4d6f6eee8929a40ac\";",
				"new-relicToken := `NRJS-8a4d6f6eee8929a40ac`",
				"new-relic_TOKEN = \"NRJS-8a4d6f6eee8929a40ac\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NewRelicBrowserAPIKey())
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
