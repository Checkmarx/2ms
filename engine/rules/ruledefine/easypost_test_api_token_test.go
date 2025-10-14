package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEasypostTestAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "EasyPostTestAPI validation",
			truePositives: []string{
				"EZTKToken=\"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"{\n    \"EZTK_token\": \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"\n}",
				"<EZTKToken>\n    EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\n</EZTKToken>",
				"var EZTKToken string = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"var EZTKToken = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTK_TOKEN := \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTKToken = EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X",
				"EZTKToken := \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTKToken := `EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X`",
				"EZTKToken = 'EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X'",
				"EZTK_TOKEN = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTK_TOKEN ?= \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTKToken = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"{\"config.ini\": \"EZTK_TOKEN=EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\\nBACKUP_ENABLED=true\"}",
				"EZTK_token: EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X",
				"EZTK_token: 'EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X'",
				"String EZTKToken = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\";",
				"$EZTKToken .= \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTKToken = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"System.setProperty(\"EZTK_TOKEN\", \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\")",
				"EZTKToken=EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X",
				"EZTK_token: \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"string EZTKToken = \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\";",
				"  \"EZTKToken\" => \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTK_TOKEN ::= \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTK_TOKEN :::= \"EZTKeBEWL0pG3VMBzVqexZ9QpZ5BC66xF4IPNP0hEm8KrpWRFm3hKdZw8X\"",
				"EZTK6th58umJpL71i8p1DkLNlgETVyGbEB9231FChRoki58zqXBQxCYUPh",
				"EZTK6th58umJpL71i8p1DkLNlgETVyGbEB9231FChRoki58zqXBQxCYUPh",
				"example.com?t=EZTK6th58umJpL71i8p1DkLNlgETVyGbEB9231FChRoki58zqXBQxCYUPh&q=1",
			},
			falsePositives: []string{
				// random base64 encoded string
				`...6wqX6fNUXA/rYqRvfQ+EZTKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6...`, // gitleaks:allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(EasyPostTestAPI())
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
