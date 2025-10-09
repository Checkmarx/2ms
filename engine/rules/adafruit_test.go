package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdafruit(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Adafruit validation",
			truePositives: []string{
				"adafruitToken=\"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruitToken = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruitToken = 5qnwhukyv3wi7h9etbfrswi6l8yiwhjl",
				"{\n    \"adafruit_token\": \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"\n}",
				"string adafruitToken = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\";",
				"$adafruitToken .= \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruit_TOKEN = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruit_TOKEN := \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruitToken=5qnwhukyv3wi7h9etbfrswi6l8yiwhjl",
				"adafruit_token: 5qnwhukyv3wi7h9etbfrswi6l8yiwhjl",
				"adafruit_token: \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"var adafruitToken string = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruitToken := \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"var adafruitToken = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"System.setProperty(\"ADAFRUIT_TOKEN\"," + " \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\")",
				"adafruit_TOKEN ?= \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"<adafruitToken>\n    5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\n</adafruitToken>",
				"adafruitToken := `5qnwhukyv3wi7h9etbfrswi6l8yiwhjl`",
				"String adafruitToken = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\";",
				"adafruitToken = \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"  \"adafruitToken\" => \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"{\"config.ini\": \"ADAFRUIT_TOKEN=5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\\nBACKUP_ENABLED=true\"}",
				"adafruit_token: '5qnwhukyv3wi7h9etbfrswi6l8yiwhjl'",
				"adafruitToken = '5qnwhukyv3wi7h9etbfrswi6l8yiwhjl'",
				"adafruit_TOKEN ::= \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
				"adafruit_TOKEN :::= \"5qnwhukyv3wi7h9etbfrswi6l8yiwhjl\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AdafruitAPIKey())
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
