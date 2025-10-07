package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRelicInsertKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NewRelicInsertKey validation",
			truePositives: []string{
				"string new-relicToken = \"NRII-0fcb463744c545c577493495c2e66c65\";",
				"String new-relicToken = \"NRII-0fcb463744c545c577493495c2e66c65\";",
				"new-relicToken = \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relic_TOKEN ?= \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"<new-relicToken>\n    NRII-0fcb463744c545c577493495c2e66c65\n</new-relicToken>",
				"new-relic_token: NRII-0fcb463744c545c577493495c2e66c65",
				"new-relicToken := \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relicToken := `NRII-0fcb463744c545c577493495c2e66c65`",
				"var new-relicToken = \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"System.setProperty(\"NEW-RELIC_TOKEN\", \"NRII-0fcb463744c545c577493495c2e66c65\")",
				"new-relic_TOKEN = \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relic_TOKEN := \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relicToken=\"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relicToken = \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relicToken=NRII-0fcb463744c545c577493495c2e66c65",
				"new-relicToken = NRII-0fcb463744c545c577493495c2e66c65",
				"{\n    \"new-relic_token\": \"NRII-0fcb463744c545c577493495c2e66c65\"\n}",
				"{\"config.ini\": \"NEW-RELIC_TOKEN=NRII-0fcb463744c545c577493495c2e66c65\\nBACKUP_ENABLED=true\"}",
				"new-relic_TOKEN ::= \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relic_TOKEN :::= \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relic_token: 'NRII-0fcb463744c545c577493495c2e66c65'",
				"new-relic_token: \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"var new-relicToken string = \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"$new-relicToken .= \"NRII-0fcb463744c545c577493495c2e66c65\"",
				"new-relicToken = 'NRII-0fcb463744c545c577493495c2e66c65'",
				"  \"new-relicToken\" => \"NRII-0fcb463744c545c577493495c2e66c65\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NewRelicInsertKey())
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
