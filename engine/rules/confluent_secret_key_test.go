package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfluentSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ConfluentSecretKey validation",
			truePositives: []string{
				"confluentToken = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluentToken = b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57",
				"{\"config.ini\": \"CONFLUENT_TOKEN=b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\\nBACKUP_ENABLED=true\"}",
				"string confluentToken = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\";",
				"confluentToken = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"System.setProperty(\"CONFLUENT_TOKEN\", \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\")",
				"confluent_TOKEN ?= \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluentToken=\"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"<confluentToken>\n    b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\n</confluentToken>",
				"confluent_token: \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"String confluentToken = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\";",
				"var confluentToken = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"$confluentToken .= \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluentToken = 'b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57'",
				"  \"confluentToken\" => \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluentToken=b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57",
				"{\n    \"confluent_token\": \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"\n}",
				"confluentToken := \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluentToken := `b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57`",
				"confluent_TOKEN = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluent_TOKEN := \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluent_TOKEN ::= \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluent_token: b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57",
				"confluent_token: 'b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57'",
				"var confluentToken string = \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
				"confluent_TOKEN :::= \"b8k6mz6l4bbcxmbfo2olbnh4m8lssqygaplqneo62s2gsysy8knkgjbup5lhrg57\"",
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
			rule := ConvertNewRuleToGitleaksRule(ConfluentSecretKey())
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
