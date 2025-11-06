package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfracostAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "InfracostAPIToken validation",
			truePositives: []string{
				"System.setProperty(\"ICO_TOKEN\", \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\")",
				"icoToken=\"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken = ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO",
				"{\n    \"ico_token\": \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"\n}",
				"ico_token: 'ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO'",
				"ico_token: \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken := `ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO`",
				"  \"icoToken\" => \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"ico_TOKEN = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken=ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO",
				"$icoToken .= \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken = 'ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO'",
				"ico_TOKEN := \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"ico_TOKEN ::= \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"ico_TOKEN ?= \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"{\"config.ini\": \"ICO_TOKEN=ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\\nBACKUP_ENABLED=true\"}",
				"<icoToken>\n    ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\n</icoToken>",
				"icoToken := \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"String icoToken = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\";",
				"var icoToken = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"ico_TOKEN :::= \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"ico_token: ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO",
				"string icoToken = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\";",
				"var icoToken string = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"icoToken = \"ico-n3hJ3w9Ezx4WIToyxMhtpqJvJ1Bq8QeO\"",
				"  variable {\n    name = \"INFRACOST_API_KEY\"\n    secret_value = \"ico-mlCr1Mn3SRcRiZMObUZOTHLcgtH2Lpgt\"\n    is_secret = true\n  }",
			},
			falsePositives: []string{
				// Low entropy
				`ico-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
				// Invalid
				`http://assets.r7.com/assets/media_box_tv_tres_colunas/video_box.ico-7a388b69018576d24b59331fd60aab0c.png`,
				`https://explosivelab.notion.site/Pianificazione-Nerdz-Ng-pubblico-1bc826ecc0994dd8915be97fc3489cde?pvs=74`,
				`http://ece252-2.uwaterloo.ca:2540/image?q=gAAAAABdHkoqb9ZaJ3q4dlzEvTgG9WYwKcD9Aw7OUXeFicO-5M5IdNDjHBpKw7KBK3nCVqtuga4yzUaFEpJn8BqA1LzZprIJBw==`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(InfracostAPIToken())
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
