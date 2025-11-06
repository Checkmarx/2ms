package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKucoinAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "KucoinAccessToken validation",
			truePositives: []string{
				"{\n    \"kucoin_token\": \"a01341bd249882e856e27bff\"\n}",
				"<kucoinToken>\n    a01341bd249882e856e27bff\n</kucoinToken>",
				"kucoin_token: a01341bd249882e856e27bff",
				"kucoin_token: \"a01341bd249882e856e27bff\"",
				"kucoinToken := `a01341bd249882e856e27bff`",
				"String kucoinToken = \"a01341bd249882e856e27bff\";",
				"System.setProperty(\"KUCOIN_TOKEN\", \"a01341bd249882e856e27bff\")",
				"kucoinToken=a01341bd249882e856e27bff",
				"string kucoinToken = \"a01341bd249882e856e27bff\";",
				"  \"kucoinToken\" => \"a01341bd249882e856e27bff\"",
				"kucoin_TOKEN :::= \"a01341bd249882e856e27bff\"",
				"kucoin_TOKEN ?= \"a01341bd249882e856e27bff\"",
				"kucoinToken = a01341bd249882e856e27bff",
				"var kucoinToken string = \"a01341bd249882e856e27bff\"",
				"kucoinToken := \"a01341bd249882e856e27bff\"",
				"$kucoinToken .= \"a01341bd249882e856e27bff\"",
				"kucoinToken = 'a01341bd249882e856e27bff'",
				"kucoin_TOKEN = \"a01341bd249882e856e27bff\"",
				"kucoin_TOKEN ::= \"a01341bd249882e856e27bff\"",
				"kucoinToken=\"a01341bd249882e856e27bff\"",
				"{\"config.ini\": \"KUCOIN_TOKEN=a01341bd249882e856e27bff\\nBACKUP_ENABLED=true\"}",
				"kucoin_token: 'a01341bd249882e856e27bff'",
				"var kucoinToken = \"a01341bd249882e856e27bff\"",
				"kucoinToken = \"a01341bd249882e856e27bff\"",
				"kucoin_TOKEN := \"a01341bd249882e856e27bff\"",
				"kucoinToken = \"a01341bd249882e856e27bff\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(KucoinAccessToken())
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
