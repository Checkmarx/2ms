package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTravisCIAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TravisCIAccessToken validation",
			truePositives: []string{
				"travis_TOKEN ::= \"2go6m1lt4focini9cgzixf\"",
				"travisToken = \"2go6m1lt4focini9cgzixf\"",
				"travisToken=2go6m1lt4focini9cgzixf",
				"{\"config.ini\": \"TRAVIS_TOKEN=2go6m1lt4focini9cgzixf\\nBACKUP_ENABLED=true\"}",
				"travis_token: '2go6m1lt4focini9cgzixf'",
				"travisToken := `2go6m1lt4focini9cgzixf`",
				"String travisToken = \"2go6m1lt4focini9cgzixf\";",
				"var travisToken = \"2go6m1lt4focini9cgzixf\"",
				"System.setProperty(\"TRAVIS_TOKEN\", \"2go6m1lt4focini9cgzixf\")",
				"$travisToken .= \"2go6m1lt4focini9cgzixf\"",
				"travisToken = '2go6m1lt4focini9cgzixf'",
				"  \"travisToken\" => \"2go6m1lt4focini9cgzixf\"",
				"travis_TOKEN = \"2go6m1lt4focini9cgzixf\"",
				"travis_TOKEN :::= \"2go6m1lt4focini9cgzixf\"",
				"travis_TOKEN ?= \"2go6m1lt4focini9cgzixf\"",
				"travisToken=\"2go6m1lt4focini9cgzixf\"",
				"travisToken = 2go6m1lt4focini9cgzixf",
				"travis_token: 2go6m1lt4focini9cgzixf",
				"string travisToken = \"2go6m1lt4focini9cgzixf\";",
				"var travisToken string = \"2go6m1lt4focini9cgzixf\"",
				"travis_TOKEN := \"2go6m1lt4focini9cgzixf\"",
				"{\n    \"travis_token\": \"2go6m1lt4focini9cgzixf\"\n}",
				"<travisToken>\n    2go6m1lt4focini9cgzixf\n</travisToken>",
				"travis_token: \"2go6m1lt4focini9cgzixf\"",
				"travisToken := \"2go6m1lt4focini9cgzixf\"",
				"travisToken = \"2go6m1lt4focini9cgzixf\"",
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
			rule := ConvertNewRuleToGitleaksRule(TravisCIAccessToken())
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
