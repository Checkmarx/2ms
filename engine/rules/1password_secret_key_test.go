package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOnePasswordSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "OnePasswordSecretKey validation",
			truePositives: []string{
				"{\n    \"1password_token\": \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"\n}",
				"{\"config.ini\": \"1PASSWORD_TOKEN=A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\\nBACKUP_ENABLED=true\"}",
				"<1passwordToken>\n    A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\n</1passwordToken>",
				"1password_token: A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0",
				"var 1passwordToken = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_token: 'A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0'",
				"var 1passwordToken string = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken := `A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0`",
				"1passwordToken = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"System.setProperty(\"1PASSWORD_TOKEN\", \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\")",
				"  \"1passwordToken\" => \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN := \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN ::= \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken = A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0",
				"1password_token: \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"string 1passwordToken = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\";",
				"1passwordToken := \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"$1passwordToken .= \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN :::= \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"String 1passwordToken = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\";",
				"1passwordToken = 'A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0'",
				"1password_TOKEN = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN ?= \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken=\"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken = \"A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken=A3-2EKK1W-2UYSORSG3GD-8S8YI-IYKJ3-5LKR0",
				"1passwordToken = 'A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0'",
				"1password_TOKEN ::= \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN ?= \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken=\"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken = A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0",
				"{\n    \"1password_token\": \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"\n}",
				"<1passwordToken>\n    A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\n</1passwordToken>",
				"1password_token: 'A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0'",
				"String 1passwordToken = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\";",
				"1passwordToken = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN := \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN :::= \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken=A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0",
				"1password_token: A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0",
				"var 1passwordToken string = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1passwordToken := `A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0`",
				"$1passwordToken .= \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"System.setProperty(\"1PASSWORD_TOKEN\", \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\")",
				"  \"1passwordToken\" => \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"1password_TOKEN = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"{\"config.ini\": \"1PASSWORD_TOKEN=A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\\nBACKUP_ENABLED=true\"}",
				"1password_token: \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"string 1passwordToken = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\";",
				"1passwordToken := \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"var 1passwordToken = \"A3-2EKK1W-2UYSOR-SG3GD-8S8YI-IYKJ3-5LKR0\"",
				"A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB",
				"A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
			},
			falsePositives: []string{
				// low entropy
				`A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX`,
				// lowercase
				`A3-xXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(OnePasswordSecretKey())
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
