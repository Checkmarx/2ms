package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAirtable(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Airtable validation",
			truePositives: []string{
				"airtableToken=i5vb6jwjeqmgmirkq",
				"airtable_token: 'i5vb6jwjeqmgmirkq'",

				"var airtableToken = \"i5vb6jwjeqmgmirkq\"",
				"airtableToken = 'i5vb6jwjeqmgmirkq'",

				"  \"airtableToken\" => \"i5vb6jwjeqmgmirkq\"",
				"airtableToken=\"i5vb6jwjeqmgmirkq\"",
				"{\n    \"airtable_token\": \"i5vb6jwjeqmgmirkq\"\n}",
				"var airtableToken string = \"i5vb6jwjeqmgmirkq\"",
				"airtableToken := \"i5vb6jwjeqmgmirkq\"",
				"$airtableToken .= \"i5vb6jwjeqmgmirkq\"",
				"System.setProperty(\"AIRTABLE_TOKEN\", \"i5vb6jwjeqmgmirkq\")",
				"airtable_TOKEN := \"i5vb6jwjeqmgmirkq\"",
				"airtable_TOKEN ?= \"i5vb6jwjeqmgmirkq\"",
				"airtableToken = \"i5vb6jwjeqmgmirkq\"",
				"{\"config.ini\": \"AIRTABLE_TOKEN=i5vb6jwjeqmgmirkq\\nBACKUP_ENABLED=true\"}",
				"<airtableToken>\n    i5vb6jwjeqmgmirkq\n</airtableToken>",
				"airtable_token: i5vb6jwjeqmgmirkq",
				"airtable_token: \"i5vb6jwjeqmgmirkq\"",
				"airtableToken := `i5vb6jwjeqmgmirkq`",
				"airtableToken = \"i5vb6jwjeqmgmirkq\"",
				"airtable_TOKEN ::= \"i5vb6jwjeqmgmirkq\"",
				"airtableToken = i5vb6jwjeqmgmirkq",
				"string airtableToken = \"i5vb6jwjeqmgmirkq\";",
				"String airtableToken = \"i5vb6jwjeqmgmirkq\";",
				"airtable_TOKEN = \"i5vb6jwjeqmgmirkq\"",
				"airtable_TOKEN :::= \"i5vb6jwjeqmgmirkq\"",
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
			rule := ConvertNewRuleToGitleaksRule(Airtable())
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
