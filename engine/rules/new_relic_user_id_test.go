package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRelicUserAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NewRelicUserID validation",
			truePositives: []string{
				"new-relicToken = 'NRAK-f3zik05inmy993vy9y1upxqgxar'",
				"System.setProperty(\"NEW-RELIC_TOKEN\", \"NRAK-f3zik05inmy993vy9y1upxqgxar\")",
				"{\n    \"new-relic_token\": \"NRAK-f3zik05inmy993vy9y1upxqgxar\"\n}",
				"{\"config.ini\": \"NEW-RELIC_TOKEN=NRAK-f3zik05inmy993vy9y1upxqgxar\\nBACKUP_ENABLED=true\"}",
				"new-relic_token: NRAK-f3zik05inmy993vy9y1upxqgxar",
				"new-relic_token: 'NRAK-f3zik05inmy993vy9y1upxqgxar'",
				"new-relic_token: \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"string new-relicToken = \"NRAK-f3zik05inmy993vy9y1upxqgxar\";",
				"new-relicToken := \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relicToken := `NRAK-f3zik05inmy993vy9y1upxqgxar`",
				"new-relicToken=\"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relicToken=NRAK-f3zik05inmy993vy9y1upxqgxar",
				"new-relicToken = NRAK-f3zik05inmy993vy9y1upxqgxar",
				"String new-relicToken = \"NRAK-f3zik05inmy993vy9y1upxqgxar\";",
				"var new-relicToken = \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relicToken = \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relic_TOKEN := \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relic_TOKEN ::= \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"<new-relicToken>\n    NRAK-f3zik05inmy993vy9y1upxqgxar\n</new-relicToken>",
				"  \"new-relicToken\" => \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relic_TOKEN = \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relic_TOKEN :::= \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relic_TOKEN ?= \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"new-relicToken = \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"var new-relicToken string = \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
				"$new-relicToken .= \"NRAK-f3zik05inmy993vy9y1upxqgxar\"",
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
			rule := ConvertNewRuleToGitleaksRule(NewRelicUserID())
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
