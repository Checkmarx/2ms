package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripeAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "StripeAccessToken validation",
			truePositives: []string{
				"String stripeToken = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\";",
				"stripe_TOKEN := \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"{\"config.ini\": \"STRIPE_TOKEN=sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\\nBACKUP_ENABLED=true\"}",
				"stripe_token: sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko",
				"stripe_token: 'sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko'",
				"string stripeToken = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\";",
				"  \"stripeToken\" => \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripe_TOKEN :::= \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripe_TOKEN ?= \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripe_token: \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken := \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken := `sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko`",
				"var stripeToken = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"System.setProperty(\"STRIPE_TOKEN\", \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\")",
				"stripe_TOKEN = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"$stripeToken .= \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken = 'sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko'",
				"stripe_TOKEN ::= \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken=\"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"stripeToken=sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko",
				"stripeToken = sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko",
				"{\n    \"stripe_token\": \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"\n}",
				"<stripeToken>\n    sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\n</stripeToken>",
				"var stripeToken string = \"sk_test_uwiz7pxjhrk159amwtbo06ra1pn9ko\"",
				"{\"config.ini\": \"STRIPE_TOKEN=sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\\nBACKUP_ENABLED=true\"}",
				"stripe_token: 'sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8'",
				"stripe_token: \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"string stripeToken = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\";",
				"var stripeToken string = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripeToken = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"System.setProperty(\"STRIPE_TOKEN\", \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\")",
				"stripeToken=\"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"<stripeToken>\n    sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\n</stripeToken>",
				"String stripeToken = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\";",
				"var stripeToken = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripeToken = 'sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8'",
				"  \"stripeToken\" => \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripe_TOKEN := \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripeToken=sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8",
				"stripeToken = sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8",
				"stripe_TOKEN = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripe_TOKEN ::= \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripe_TOKEN :::= \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripe_TOKEN ?= \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripeToken = \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"{\n    \"stripe_token\": \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"\n}",
				"stripe_token: sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8",
				"stripeToken := \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"stripeToken := `sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8`",
				"$stripeToken .= \"sk_prod_uwiz7pxjhrk159amwtbo06ra1pn9ko8c0tpfdil0q84v7q1y7c7ozls27yklo7o7ih13z9pogrjl85wogmbrtnfm9jecritgxg8\"",
				"sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs",
				"rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon",
			},
			falsePositives: []string{"nonMatchingToken := \"task_test_x3sj78ag8rqrwmz88zqhxh4fv64h00\""},
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
			rule := ConvertNewRuleToGitleaksRule(StripeAccessToken())
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
