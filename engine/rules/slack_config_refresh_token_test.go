package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackConfigurationRefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackConfigurationRefreshToken validation",
			truePositives: []string{
				"refreshToken := \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken := `xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg`",
				"var refreshToken = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"  \"refreshToken\" => \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refresh_TOKEN = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refresh_TOKEN := \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refresh_token: xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg",
				"refresh_token: 'xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg'",
				"string refreshToken = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\";",
				"System.setProperty(\"REFRESH_TOKEN\", \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\")",
				"refresh_TOKEN :::= \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refresh_TOKEN ?= \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken=\"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken = xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg",
				"{\"config.ini\": \"REFRESH_TOKEN=xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\\nBACKUP_ENABLED=true\"}",
				"String refreshToken = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\";",
				"$refreshToken .= \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken = 'xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg'",
				"refreshToken = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refresh_TOKEN ::= \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"refreshToken=xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg",
				"{\n    \"refresh_token\": \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"\n}",
				"<refreshToken>\n    xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\n</refreshToken>",
				"refresh_token: \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"var refreshToken string = \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"\"refresh_token1\": \"xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg\"",
				"\"refresh_token2\": \"xoxe-1-My0xLTM0MTQwNDE0MDE3Ni01MTgyMDc1NDk2MDgwLTU0MjQ1NjIwNzgxODEtNGJkYTZhYTUxY2M1ODk3ZTNkN2YzMTgxMDI1ZDQzNzgwNWY4NWQ0ODdhZGIzM2ViOGI0MTM0MjdlNGVmYzQ4Ng\"",
				"\"refresh_token3\": \"xoxe-1-c08542voqwczsr5is57ex9w0m0yff8gkflgl72dlx20rqd3rcubxvo9m5uf4x9337nloir4zkkvftd2kaimsbu2hl0ladiol69gwz15s5qqtmh69f0ipor0p0is98v6qo7ci3sv0fo25rmhuu6\"",
			},
			falsePositives: []string{
				"xoxe-1-xxx",
				"XOxE-RROAmw, Home and Garden, 5:24, 20120323",
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
			rule := ConvertNewRuleToGitleaksRule(SlackConfigurationRefreshToken())
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
