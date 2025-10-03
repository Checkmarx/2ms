package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPostManAPI(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PostManAPI validation",
			truePositives: []string{
				"postmanAPItoken_TOKEN ::= \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken=PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe",
				"{\"config.ini\": \"POSTMANAPITOKEN_TOKEN=PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\\nBACKUP_ENABLED=true\"}",
				"postmanAPItoken_token: 'PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe'",
				"System.setProperty(\"POSTMANAPITOKEN_TOKEN\", \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\")",
				"postmanAPItoken_TOKEN :::= \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken = PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe",
				"<postmanAPItokenToken>\n    PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\n</postmanAPItokenToken>",
				"postmanAPItoken_TOKEN := \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItoken_TOKEN ?= \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"{\n    \"postmanAPItoken_token\": \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"\n}",
				"postmanAPItoken_token: PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe",
				"postmanAPItoken_token: \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"string postmanAPItokenToken = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\";",
				"postmanAPItokenToken := \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"String postmanAPItokenToken = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\";",
				"$postmanAPItokenToken .= \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken=\"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"var postmanAPItokenToken string = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken := `PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe`",
				"var postmanAPItokenToken = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItokenToken = 'PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe'",
				"  \"postmanAPItokenToken\" => \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
				"postmanAPItoken_TOKEN = \"PMAK-8b614192e19ce588446c26b0-8b614192e19ce588446c26b057fe9cabbe\"",
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
			rule := ConvertNewRuleToGitleaksRule(PostManAPI())
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
