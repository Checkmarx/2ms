package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackLegacyToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackLegacyToken validation",
			truePositives: []string{

				"slack_TOKEN = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"{\n    \"slack_token\": \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"\n}",
				"slackToken := `xoxs-416843729158-132049654-5609968301-e708ba56e1`",
				"var slackToken = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"  \"slackToken\" => \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slack_TOKEN :::= \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slack_TOKEN ?= \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken=\"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken=xoxs-416843729158-132049654-5609968301-e708ba56e1",
				"slackToken = xoxs-416843729158-132049654-5609968301-e708ba56e1",
				"slack_token: 'xoxs-416843729158-132049654-5609968301-e708ba56e1'",
				"string slackToken = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\";",
				"var slackToken string = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"String slackToken = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\";",
				"slack_TOKEN := \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"$slackToken .= \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken = 'xoxs-416843729158-132049654-5609968301-e708ba56e1'",
				"System.setProperty(\"SLACK_TOKEN\", \"xoxs-416843729158-132049654-5609968301-e708ba56e1\")",
				"slack_TOKEN ::= \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"{\"config.ini\": \"SLACK_TOKEN=xoxs-416843729158-132049654-5609968301-e708ba56e1\\nBACKUP_ENABLED=true\"}",
				"<slackToken>\n    xoxs-416843729158-132049654-5609968301-e708ba56e1\n</slackToken>",
				"slack_token: xoxs-416843729158-132049654-5609968301-e708ba56e1",
				"slack_token: \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken := \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"slackToken = \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"\"access_token1\": \"xoxs-3206092076-3204538285-3743137121-836b042620\"",
				"\"access_token2\": \"xoxs-416843729158-132049654-5609968301-e708ba56e1\"",
				"\"access_token3\": \"xoxs-420083410720-421837374423-440811613314-977844f625b707d5b0b268206dbc92cbc85feef3e71b08e44815a8e6e7657190\"",
				"\"access_token4\": \"xoxs-4829527689-4829527691-4814341714-d0346ec616\"",
				"\"access_token5\": \"xoxs-155191149137-155868813314-338998331396-9f6d235915\"",
				"\"access_token6\": \"xoxs-7376551832-0140200885-0140200885-c7a0a46c4f\"",
				"\"access_token7\": \"xoxo-523423-234243-234233-e039d02840a0b9379c\"",
			},
			falsePositives: []string{
				"https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg",
				"https://lh3.googleusercontent.com/-tWXjX3LUD6w/Ua4La_N5E2I/AAAAAAAAACg/qcm19xbEYa4/s640/EXO-XOXO-teaser-exo-k-34521098-720-516.jpg",
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
			rule := ConvertNewRuleToGitleaksRule(SlackLegacyToken())
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
