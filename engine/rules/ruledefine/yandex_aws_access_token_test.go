package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYandexAWSAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "YandexAWSAccessToken validation",
			truePositives: []string{
				"String yandexToken = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\";",
				"System.setProperty(\"YANDEX_TOKEN\", \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\")",
				"yandex_TOKEN ?= \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken=\"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken = YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8",
				"yandex_token: \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"$yandexToken .= \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken = 'YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8'",
				"yandexToken = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandex_TOKEN := \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"{\n    \"yandex_token\": \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"\n}",
				"yandex_token: YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8",
				"string yandexToken = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\";",
				"var yandexToken string = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"var yandexToken = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"  \"yandexToken\" => \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandex_TOKEN ::= \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandex_TOKEN :::= \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken=YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8",
				"<yandexToken>\n    YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\n</yandexToken>",
				"yandex_TOKEN = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken = \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"{\"config.ini\": \"YANDEX_TOKEN=YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\\nBACKUP_ENABLED=true\"}",
				"yandex_token: 'YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8'",
				"yandexToken := \"YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8\"",
				"yandexToken := `YCtsE8_hKXjCMj0Bj5qgG1M7yaLpAr43qYTCt9g8`",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(YandexAWSAccessToken())
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
