package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTelegramBotToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TelegramBotToken validation",
			truePositives: []string{
				"string telegramToken = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\";",
				"var telegramToken = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegram_TOKEN ::= \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken = 99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_",
				"{\"config.ini\": \"TELEGRAM_TOKEN=99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\\nBACKUP_ENABLED=true\"}",
				"<telegramToken>\n    99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\n</telegramToken>",
				"telegram_token: \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"var telegramToken string = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"$telegramToken .= \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"  \"telegramToken\" => \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken=\"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegram_token: 99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_",
				"telegramToken := \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken := `99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_`",
				"System.setProperty(\"TELEGRAM_TOKEN\", \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\")",
				"telegram_TOKEN = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegram_TOKEN :::= \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegram_TOKEN ?= \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken=99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_",
				"{\n    \"telegram_token\": \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"\n}",
				"telegram_token: '99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_'",
				"String telegramToken = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\";",
				"telegramToken = '99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_'",
				"telegram_TOKEN := \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_\"",
				"telegramToken = '99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy'",
				"telegramToken = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegram_TOKEN = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegram_TOKEN :::= \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegramToken = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"{\n    \"telegram_token\": \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"\n}",
				"{\"config.ini\": \"TELEGRAM_TOKEN=99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\\nBACKUP_ENABLED=true\"}",
				"string telegramToken = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\";",
				"telegram_TOKEN := \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegram_TOKEN ::= \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegram_TOKEN ?= \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"var telegramToken string = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"var telegramToken = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"System.setProperty(\"TELEGRAM_TOKEN\", \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\")",
				"  \"telegramToken\" => \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegramToken=\"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegramToken=99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy",
				"telegramToken = 99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy",
				"telegram_token: '99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy'",
				"telegram_token: \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"telegramToken := \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"String telegramToken = \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\";",
				"$telegramToken .= \"99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\"",
				"<telegramToken>\n    99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy\n</telegramToken>",
				"telegram_token: 99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy",
				"telegramToken := `99224:Ap_uwlvfqq62y58f-99ogq005plyzmqosxy`",
				"<telegramToken>\n    9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\n</telegramToken>",
				"telegramToken := \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"String telegramToken = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\";",
				"var telegramToken = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegram_TOKEN ?= \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegramToken=\"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"{\"config.ini\": \"TELEGRAM_TOKEN=9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\\nBACKUP_ENABLED=true\"}",
				"telegram_token: '9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux'",
				"telegramToken := `9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux`",
				"telegramToken = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegram_TOKEN := \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"{\n    \"telegram_token\": \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"\n}",
				"telegram_token: 9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux",
				"telegram_token: \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"var telegramToken string = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegramToken = '9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux'",
				"telegram_TOKEN = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegram_TOKEN ::= \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegram_TOKEN :::= \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"string telegramToken = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\";",
				"$telegramToken .= \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"System.setProperty(\"TELEGRAM_TOKEN\", \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\")",
				"  \"telegramToken\" => \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegramToken = \"9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux\"",
				"telegramToken=9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux",
				"telegramToken = 9922473881378013:Ay58f-99ogq005plyzmqosxywg_ipzq3wux",
				"TELEGRAM_API_TOKEN = 99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_",
				"telegram bot: 99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_",
			},
			falsePositives: []string{
				"telegram_api_token = \"9922:Asp_uwlvfqq62y58f-99ogq005plyzmqosx\"",
				"telegram_api_token = \"99224738813780132:A58f-99ogq005plyzmqosxywg_ipzq3wuxn\"",
				"telegram_api_token = \"<xsd:element name=\"AgencyIdentificationCode\" type=\"clm99224:AgencyIdentificationCodeContentType\"/>\"",
				"telegram_api_token = \"token:\"clm99224:AgencyIdentificationCodeContentType\"\"",
				"telegram_api_token = \"<xsd:element name=\"AgencyIdentificationCode\" type=\"clm99224738:AgencyIdentificationCodeContentType\"/>\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:Ahellowlvfqq62y58f-99ogq005plyzmqosxywg_\"\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:A-some-other-thing-wlvfqq62y58f-99ogq005plyzmqosxywg_\"\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:A_wlvfqq62y58f-99ogq005plyzmqosxywg_\"\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_hello\"\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:Awlvfqq62y58f-99ogq005plyzmqosxywg_-some-other-thing\"\"",
				"telegram_api_token = \"telegram_api_token = \"99224738:A_wlvfqq62y58f-99ogq005plyzmqosxywg__\"\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(TelegramBotToken())
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
