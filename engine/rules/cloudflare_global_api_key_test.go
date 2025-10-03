package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudflareGlobalApiKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "CloudflareGlobalAPIKey validation",
			truePositives: []string{
				"cloudflare_token: '037e798550e45925c347151d30f5fe3405a1e'",
				"cloudflare_token: \"037e798550e45925c347151d30f5fe3405a1e\"",
				"string cloudflareToken = \"037e798550e45925c347151d30f5fe3405a1e\";",
				"var cloudflareToken = \"037e798550e45925c347151d30f5fe3405a1e\"",
				"$cloudflareToken .= \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflareToken = '037e798550e45925c347151d30f5fe3405a1e'",
				"<cloudflareToken>\n    037e798550e45925c347151d30f5fe3405a1e\n</cloudflareToken>",
				"cloudflareToken := \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflareToken = \"037e798550e45925c347151d30f5fe3405a1e\"",
				"System.setProperty(\"CLOUDFLARE_TOKEN\", \"037e798550e45925c347151d30f5fe3405a1e\")",
				"cloudflare_TOKEN := \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflare_TOKEN ::= \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflareToken = \"037e798550e45925c347151d30f5fe3405a1e\"",
				"{\n    \"cloudflare_token\": \"037e798550e45925c347151d30f5fe3405a1e\"\n}",
				"var cloudflareToken string = \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflareToken := `037e798550e45925c347151d30f5fe3405a1e`",
				"cloudflareToken=\"037e798550e45925c347151d30f5fe3405a1e\"",
				"{\"config.ini\": \"CLOUDFLARE_TOKEN=037e798550e45925c347151d30f5fe3405a1e\\nBACKUP_ENABLED=true\"}",
				"cloudflare_token: 037e798550e45925c347151d30f5fe3405a1e",
				"String cloudflareToken = \"037e798550e45925c347151d30f5fe3405a1e\";",
				"  \"cloudflareToken\" => \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflare_TOKEN = \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflare_TOKEN :::= \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflare_TOKEN ?= \"037e798550e45925c347151d30f5fe3405a1e\"",
				"cloudflareToken=037e798550e45925c347151d30f5fe3405a1e",
				"cloudflareToken = 037e798550e45925c347151d30f5fe3405a1e",
			},
			falsePositives: []string{
				`cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, // gitleaks:allow
				`CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc`,    // gitleaks:allow
				`cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`,          // gitleaks:allow

				`CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5`,
				`CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed`,
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
			rule := ConvertNewRuleToGitleaksRule(CloudflareGlobalAPIKey())
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
