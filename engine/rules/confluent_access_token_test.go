package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfluentAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ConfluentAccessToken validation",
			truePositives: []string{
				"confluent_TOKEN := \"efvewo3ddgtawgtv\"",
				"confluentToken=efvewo3ddgtawgtv",
				"confluentToken = efvewo3ddgtawgtv",
				"{\n    \"confluent_token\": \"efvewo3ddgtawgtv\"\n}",
				"confluent_token: \"efvewo3ddgtawgtv\"",
				"var confluentToken string = \"efvewo3ddgtawgtv\"",
				"confluentToken := \"efvewo3ddgtawgtv\"",
				"String confluentToken = \"efvewo3ddgtawgtv\";",
				"var confluentToken = \"efvewo3ddgtawgtv\"",
				"confluentToken=\"efvewo3ddgtawgtv\"",
				"confluent_token: 'efvewo3ddgtawgtv'",
				"string confluentToken = \"efvewo3ddgtawgtv\";",
				"confluentToken = 'efvewo3ddgtawgtv'",
				"confluentToken = \"efvewo3ddgtawgtv\"",
				"  \"confluentToken\" => \"efvewo3ddgtawgtv\"",
				"confluent_TOKEN = \"efvewo3ddgtawgtv\"",
				"confluent_TOKEN :::= \"efvewo3ddgtawgtv\"",
				"confluent_token: efvewo3ddgtawgtv",
				"$confluentToken .= \"efvewo3ddgtawgtv\"",
				"confluent_TOKEN ::= \"efvewo3ddgtawgtv\"",
				"confluent_TOKEN ?= \"efvewo3ddgtawgtv\"",
				"confluentToken = \"efvewo3ddgtawgtv\"",
				"{\"config.ini\": \"CONFLUENT_TOKEN=efvewo3ddgtawgtv\\nBACKUP_ENABLED=true\"}",
				"<confluentToken>\n    efvewo3ddgtawgtv\n</confluentToken>",
				"confluentToken := `efvewo3ddgtawgtv`",
				"System.setProperty(\"CONFLUENT_TOKEN\", \"efvewo3ddgtawgtv\")",
			},
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
			rule := ConvertNewRuleToGitleaksRule(ConfluentAccessToken())
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
