package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultServiceToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "VaultServiceToken validation",
			truePositives: []string{
				"vault_api_token = \"s.0d2vTmO3fW38paBPm3qKpGh5\"",
				"token: s.ZC9Ecf4M5g9o34Q6RkzGsj0z",
				"vault_api_token = \"hvs.0EoIfeDt4LhH6cnr3xZFnZzrqTnIiLF2VpY78jL7Ssp8kJ7QKsxYYa179yPOrg07BPZNlJIF264cl_501SZ49CBrcR\"",
				"-vaultToken hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg\"",
			},
			falsePositives: []string{
				// Old
				`  credentials: new AWS.SharedIniFileCredentials({ profile: '<YOUR_PROFILE>' })`,                              // word boundary start
				`INFO 4 --- [           main] o.s.b.f.s.DefaultListableBeanFactory     : Overriding bean definition for bean`, // word boundary end
				`s.xxxxxxxxxxxxxxxxxxxxxxxx`,        // low entropy
				`s.THISSTRINGISALLUPPERCASE`,        // uppercase
				`s.thisstringisalllowercase`,        // lowercase
				`s.AcceptanceTimeoutSeconds `,       // pascal-case
				`s.makeKubeConfigController = args`, // camel-case
				// New
				`hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
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
			rule := ConvertNewRuleToGitleaksRule(VaultServiceToken())
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
