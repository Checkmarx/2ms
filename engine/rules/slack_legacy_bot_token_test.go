package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSlackLegacyBotToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackLegacyBotToken validation",
			truePositives: []string{
				"slackToken=xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"string slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\";",
				"slackToken = 'xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1'",
				"slack_TOKEN = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN :::= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken=\"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"{\n    \"slack_token\": \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"\n}",
				"{\"config.ini\": \"SLACK_TOKEN=xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\\nBACKUP_ENABLED=true\"}",
				"<slackToken>\n    xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\n</slackToken>",
				"slack_token: xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"slackToken := \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken := `xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1`",
				"slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken = xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1",
				"var slackToken string = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"System.setProperty(\"SLACK_TOKEN\", \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\")",
				"  \"slackToken\" => \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN := \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN ::= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_TOKEN ?= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"slack_token: 'xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1'",
				"slack_token: \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"String slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\";",
				"var slackToken = \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"$slackToken .= \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"\"bot_token1\": \"xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1\"",
				"\"bot_token2\": \"xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP\"",
				"\"bot_token3\": \"xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1\"",
				"\"bot_token4\": \"xoxb-123456789012-Xw937qtWSXJss1lFaKe\"",
				"\"bot_token5\": \"xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS\"",
				"\"bot_token6\": \"xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi\"",
				"\"bot_token7\": \"xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK\"",
				"\"bot_token8\": \"xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI\"",
				"\"bot_token9\": \"xoxb-50014434-slacktokenx29U9X1bQ\"",
				"\"bot_token10\": \"xoxb-6036579657-ks3e7l1cfdqnlt5zdmsb9suj",
				"\"bot_token11\": \"xoxb-603657965729-ks3e7l1cfdqnlt5zdmsb9su",
			},
			falsePositives: []string{
				"xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
				"xoxb-Slack_BOT_TOKEN",
				"xoxb-abcdef-abcdef",
				// "xoxb-0000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tps := utils.GenerateSampleSecrets("slack", "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1")
			tps = append(tps,
				// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#LL42C38-L42C80
				`"bot_token1": "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"`, // gitleaks:allow
				// https://heejune.me/2018/08/01/crashdump-analysis-automation-using-slackbot-python-cdb-from-windows/
				`"bot_token2": "xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP"`, // gitleaks:allow
				// https://github.com/praetorian-inc/noseyparker/blob/16e0e5768fd14ea54f6c9a058566184d88343bb4/crates/noseyparker/data/default/rules/slack.yml#L15
				`"bot_token3": "xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1"`, // gitleaks:allow
				// https://github.com/pulumi/examples/blob/32d9047c19c2a9380c04e57a764321c25eef45b0/aws-js-sqs-slack/README.md?plain=1#L39
				`"bot_token4": "xoxb-123456789012-Xw937qtWSXJss1lFaKe"`, // gitleaks:allow
				// https://github.com/ilyasProgrammer/Odoo-eBay-Amazon/blob/a9c4a8a7548b19027bc0fd904f8ae9249248a293/custom_logging/models.py#LL9C24-L9C66
				`"bot_token5": "xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS"`, // gitleaks:allow
				// https://github.com/jay-johnson/sci-pype/blob/6bff42ea4eb32d35b9f223db312e4cd0d3911100/src/pycore.py#L37
				`"bot_token6": "xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi"`, // gitleaks:allow
				// https://github.com/logicmoo/logicmoo_workspace/blob/2e1794f596121c9949deb3bfbd30d5b027a51d3d/packs_sys/slack_prolog/prolog/slack_client_old.pl#L28
				`"bot_token7": "xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK"`, // gitleaks:allow
				// https://github.com/sbarski/serverless-chatbot/blob/7d556897486f3fd53795907b7e33252e5cc6b3a3/Lesson%203/serverless.yml#L38
				`"bot_token8": "xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI"`,                                                                       // gitleaks:allow
				`"bot_token9": "xoxb-50014434-slacktokenx29U9X1bQ"`,                                                                               // gitleaks:allow
				`"bot_token10": `+fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.AlphaNumeric("24"))), // gitleaks:allow
				`"bot_token11": `+fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(utils.Numeric("12")), secrets.NewSecret(utils.AlphaNumeric("23"))), // gitleaks:allow
			)
			fmt.Println("truePositives := []string{")
			for _, s := range tps {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(SlackLegacyBotToken())
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
