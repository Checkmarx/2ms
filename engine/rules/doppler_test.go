package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDopplerAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Doppler validation",
			truePositives: []string{
				"dopplerToken := \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"var dopplerToken = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"$dopplerToken .= \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"dopplerToken=dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v",
				"doppler_token: \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"dopplerToken = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"System.setProperty(\"DOPPLER_TOKEN\", \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\")",
				"doppler_TOKEN = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"doppler_TOKEN :::= \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"doppler_TOKEN ?= \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"dopplerToken = dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v",
				"<dopplerToken>\n    dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\n</dopplerToken>",
				"doppler_token: dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v",
				"string dopplerToken = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\";",
				"doppler_TOKEN := \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"{\n    \"doppler_token\": \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"\n}",
				"dopplerToken := `dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v`",
				"String dopplerToken = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\";",
				"dopplerToken = 'dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v'",
				"  \"dopplerToken\" => \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"doppler_TOKEN ::= \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"dopplerToken=\"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"dopplerToken = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
				"{\"config.ini\": \"DOPPLER_TOKEN=dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\\nBACKUP_ENABLED=true\"}",
				"doppler_token: 'dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v'",
				"var dopplerToken string = \"dp.pt.3821ku9kup9sz6dad3bwmccmsxvd8qybquupsyqwr8v\"",
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
			rule := ConvertNewRuleToGitleaksRule(Doppler())
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
