package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefect(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Prefect validation",
			truePositives: []string{
				"<api-tokenToken>\n    pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\n</api-tokenToken>",
				"api-tokenToken := \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"  \"api-tokenToken\" => \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_TOKEN = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_TOKEN ?= \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-tokenToken = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_token: 'pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u'",
				"api-token_token: \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"string api-tokenToken = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\";",
				"api-tokenToken := `pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u`",
				"$api-tokenToken .= \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-tokenToken = 'pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u'",
				"System.setProperty(\"API-TOKEN_TOKEN\", \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\")",
				"api-tokenToken=\"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_token: pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u",
				"var api-tokenToken string = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"String api-tokenToken = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\";",
				"api-token_TOKEN := \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_TOKEN :::= \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"{\n    \"api-token_token\": \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"\n}",
				"{\"config.ini\": \"API-TOKEN_TOKEN=pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\\nBACKUP_ENABLED=true\"}",
				"var api-tokenToken = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-tokenToken = \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-token_TOKEN ::= \"pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u\"",
				"api-tokenToken=pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u",
				"api-tokenToken = pnu_473ax9mdi5larwiwk7k16turpxdh5kuyir0u",
			},
			falsePositives: []string{
				`PREFECT_API_KEY = "pnu_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Prefect())
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
