package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBittrexSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "BittrexSecretKey validation",
			truePositives: []string{
				"bittrexToken=\"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken = \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken=ewyszm781qih0ok9d52bkevxzrchqb7h",
				"{\"config.ini\": \"BITTREX_TOKEN=ewyszm781qih0ok9d52bkevxzrchqb7h\\nBACKUP_ENABLED=true\"}",
				"bittrexToken := \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken := `ewyszm781qih0ok9d52bkevxzrchqb7h`",
				"bittrex_TOKEN = \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken = ewyszm781qih0ok9d52bkevxzrchqb7h",
				"bittrex_token: 'ewyszm781qih0ok9d52bkevxzrchqb7h'",
				"bittrex_token: \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"string bittrexToken = \"ewyszm781qih0ok9d52bkevxzrchqb7h\";",
				"var bittrexToken string = \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"String bittrexToken = \"ewyszm781qih0ok9d52bkevxzrchqb7h\";",
				"var bittrexToken = \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken = 'ewyszm781qih0ok9d52bkevxzrchqb7h'",
				"{\n    \"bittrex_token\": \"ewyszm781qih0ok9d52bkevxzrchqb7h\"\n}",
				"bittrex_token: ewyszm781qih0ok9d52bkevxzrchqb7h",
				"$bittrexToken .= \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrexToken = \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"System.setProperty(\"BITTREX_TOKEN\", \"ewyszm781qih0ok9d52bkevxzrchqb7h\")",
				"  \"bittrexToken\" => \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrex_TOKEN :::= \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrex_TOKEN ?= \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"<bittrexToken>\n    ewyszm781qih0ok9d52bkevxzrchqb7h\n</bittrexToken>",
				"bittrex_TOKEN := \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
				"bittrex_TOKEN ::= \"ewyszm781qih0ok9d52bkevxzrchqb7h\"",
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
			rule := ConvertNewRuleToGitleaksRule(BittrexSecretKey())
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
