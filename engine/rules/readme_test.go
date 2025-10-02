package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadMe(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ReadMe validation",
			truePositives: []string{
				"<api-tokenToken>\n    rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\n</api-tokenToken>",
				"api-token_token: 'rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj'",
				"api-token_token: \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"var api-tokenToken = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"$api-tokenToken .= \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"  \"api-tokenToken\" => \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-token_TOKEN = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-tokenToken = rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj",
				"{\n    \"api-token_token\": \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"\n}",
				"api-token_token: rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj",
				"string api-tokenToken = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\";",
				"var api-tokenToken string = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-tokenToken := `rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj`",
				"api-tokenToken = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-tokenToken=rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj",
				"api-tokenToken := \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"System.setProperty(\"API-TOKEN_TOKEN\", \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\")",
				"api-token_TOKEN ::= \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-token_TOKEN ?= \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-tokenToken=\"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-tokenToken = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"{\"config.ini\": \"API-TOKEN_TOKEN=rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\\nBACKUP_ENABLED=true\"}",
				"String api-tokenToken = \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\";",
				"api-tokenToken = 'rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj'",
				"api-token_TOKEN := \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
				"api-token_TOKEN :::= \"rdme_jg7f8khrj7igpt1narqzfgk7sgw8ah1cfy4il3m3gpgxyd8k8zwvzcqbxrl059jo1ls3hj\"",
			},
			falsePositives: []string{
				`const API_KEY = 'rdme_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`,
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
			rule := ConvertNewRuleToGitleaksRule(ReadMe())
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
