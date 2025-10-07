package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudflareApiKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "CloudflareAPIKey validation",
			truePositives: []string{
				"cloudflare_token: 'zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0'",
				"var cloudflareToken string = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken = 'zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0'",
				"cloudflare_TOKEN :::= \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken=zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0",
				"{\n    \"cloudflare_token\": \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"\n}",
				"{\"config.ini\": \"CLOUDFLARE_TOKEN=zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\\nBACKUP_ENABLED=true\"}",
				"cloudflare_token: \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"$cloudflareToken .= \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"System.setProperty(\"CLOUDFLARE_TOKEN\", \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\")",
				"  \"cloudflareToken\" => \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"<cloudflareToken>\n    zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\n</cloudflareToken>",
				"cloudflareToken := `zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0`",
				"cloudflare_TOKEN = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflare_TOKEN ::= \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflare_TOKEN ?= \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken=\"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflare_token: zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0",
				"string cloudflareToken = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\";",
				"cloudflareToken := \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"String cloudflareToken = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\";",
				"var cloudflareToken = \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflare_TOKEN := \"zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0\"",
				"cloudflareToken = zvsxz2oifi661ya-p1yh8zpog1n8o00aepble9j0",
				// cloudfare_api_keys
				"cloudflare_api_key = \"Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4\"",
				"CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc",
				"cloudflare: \"oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX\"",
			},
			falsePositives: []string{
				`cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`, // gitleaks:allow
				`CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c`,    // gitleaks:allow
				`cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`,                 // gitleaks:allow

				`CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5`,
				`CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(CloudflareAPIKey())
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
