package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackUserToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackUserToken validation",
			truePositives: []string{
				"var userToken = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"string userToken = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\";",
				"$userToken .= \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken = 'xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef'",
				"userToken = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"user_TOKEN = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"user_TOKEN ::= \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"user_TOKEN :::= \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"user_TOKEN ?= \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken=\"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken = xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef",
				"user_token: xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef",
				"user_token: 'xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef'",
				"userToken := \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"System.setProperty(\"USER_TOKEN\", \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\")",
				"user_TOKEN := \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken=xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef",
				"String userToken = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\";",
				"  \"userToken\" => \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"{\n    \"user_token\": \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"\n}",
				"{\"config.ini\": \"USER_TOKEN=xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\\nBACKUP_ENABLED=true\"}",
				"<userToken>\n    xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\n</userToken>",
				"user_token: \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"var userToken string = \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"userToken := `xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef`",
				"\"user_token1\": \"xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef\"",
				"\"user_token2\": \"xoxp-283316862324-298911817009-298923149681-44f585044dace54f5701618e97cd1c0b\"",
				"\"user_token3\": \"xoxp-11873098179-111402824422-234336993777-b96c9fb3b69f82ebb79d12f280779de1\"",
				"\"user_token4\": \"xoxp-254112160503-252950188691-252375361712-6cbf56aada30951a9d310a5f23d032a0\"",
				"\"user_token5\": \"xoxp-4614724432022-4621207627011-5182682871568-1ddad9823e8528ad0f4944dfa3c6fc6c\"",
				"\"user_token6\": \"xoxp-364816792900-3648167929002-3648167929002-3gawlqb3u5scci6f7dohq8oibmgpkjqx\"",
				"\"url_private\": \"https:\\/\\/files.slack.com\\/files-pri\\/T04MCQMEXQ9-F04MAA1PKE3\\/image.png?t=xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206\"",
			},
			falsePositives: []string{
				`https://docs.google.com/document/d/1W7KCxOxP-1Fy5EyF2lbJGE2WuKmu5v0suYqoHas1jRM`,
				`"token1": "xoxp-1234567890"`, // gitleaks:allow
				`"token2": "xoxp-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`, // gitleaks:allow
				`"token3": "xoxp-1234-1234-1234-4ddbc191d40ee098cbaae6f3523ada2d"`,                    // gitleaks:allow
				`"token4": "xoxp-572370529330-573807301142-572331691188-####################"`,        // gitleaks:allow
				// This technically matches the pattern but is an obvious false positive.
				// `"token5": "xoxp-000000000000-000000000000-000000000000-00000000000000000000000000000000"`, // gitleaks:allow
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
			rule := ConvertNewRuleToGitleaksRule(SlackUserToken())
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
