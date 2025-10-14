package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYandexAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "YandexAPIKey validation",
			truePositives: []string{
				"yandexToken=\"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"string yandexToken = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\";",
				"yandexToken = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"System.setProperty(\"YANDEX_TOKEN\", \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\")",
				"yandex_TOKEN :::= \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandexToken=AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E",
				"yandexToken = AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E",
				"<yandexToken>\n    AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\n</yandexToken>",
				"yandex_token: AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E",
				"yandex_token: 'AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E'",
				"var yandexToken = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandexToken = 'AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E'",
				"  \"yandexToken\" => \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandexToken = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"{\n    \"yandex_token\": \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"\n}",
				"{\"config.ini\": \"YANDEX_TOKEN=AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\\nBACKUP_ENABLED=true\"}",
				"yandex_token: \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"var yandexToken string = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandexToken := \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandexToken := `AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E`",
				"yandex_TOKEN ::= \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"String yandexToken = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\";",
				"$yandexToken .= \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandex_TOKEN = \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandex_TOKEN := \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
				"yandex_TOKEN ?= \"AQVN0rfxQoNRvKMMVcQGtKoWTtowcDnte4k1M0E\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(YandexAPIKey())
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
