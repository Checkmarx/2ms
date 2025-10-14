package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYandexAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "YandexAccessToken validation",
			truePositives: []string{
				"System.setProperty(\"YANDEX_TOKEN\", \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\")",
				"yandex_TOKEN = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandex_TOKEN :::= \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandex_token: 't1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme='",
				"yandex_token: \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"var yandexToken string = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken := \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"$yandexToken .= \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken=t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=",
				"yandexToken = t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=",
				"{\"config.ini\": \"YANDEX_TOKEN=t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\\nBACKUP_ENABLED=true\"}",
				"<yandexToken>\n    t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\n</yandexToken>",
				"yandexToken := `t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=`",
				"  \"yandexToken\" => \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandex_TOKEN := \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandex_TOKEN ?= \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"String yandexToken = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\";",
				"var yandexToken = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken = 't1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme='",
				"yandex_TOKEN ::= \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken=\"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"yandexToken = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"",
				"{\n    \"yandex_token\": \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\"\n}",
				"yandex_token: t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=",
				"string yandexToken = \"t1.W=.ex0zPVfNiX7zHnd1oPKgoxs2BIdBfzOcGplZudFfLMWFPEL5ToH3jSUYoV9vtTYMMPQ153udKDBDFh2QxWipme=\";",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(YandexAccessToken())
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
