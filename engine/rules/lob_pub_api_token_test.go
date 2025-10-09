package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLobPubAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LobPubAPIToken validation",
			truePositives: []string{
				"<lobToken>\n    test_pub_bfe696d078118e777aecbd634939183\n</lobToken>",
				"lob_token: test_pub_bfe696d078118e777aecbd634939183",
				"lob_token: \"test_pub_bfe696d078118e777aecbd634939183\"",
				"string lobToken = \"test_pub_bfe696d078118e777aecbd634939183\";",
				"lobToken := \"test_pub_bfe696d078118e777aecbd634939183\"",
				"var lobToken = \"test_pub_bfe696d078118e777aecbd634939183\"",
				"System.setProperty(\"LOB_TOKEN\", \"test_pub_bfe696d078118e777aecbd634939183\")",
				"lob_TOKEN = \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lobToken = test_pub_bfe696d078118e777aecbd634939183",
				"{\"config.ini\": \"LOB_TOKEN=test_pub_bfe696d078118e777aecbd634939183\\nBACKUP_ENABLED=true\"}",
				"lobToken := `test_pub_bfe696d078118e777aecbd634939183`",
				"String lobToken = \"test_pub_bfe696d078118e777aecbd634939183\";",
				"lobToken = \"test_pub_bfe696d078118e777aecbd634939183\"",
				"  \"lobToken\" => \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lob_TOKEN ::= \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lobToken=\"test_pub_bfe696d078118e777aecbd634939183\"",
				"lobToken = \"test_pub_bfe696d078118e777aecbd634939183\"",
				"{\n    \"lob_token\": \"test_pub_bfe696d078118e777aecbd634939183\"\n}",
				"var lobToken string = \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lobToken = 'test_pub_bfe696d078118e777aecbd634939183'",
				"lob_TOKEN :::= \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lobToken=test_pub_bfe696d078118e777aecbd634939183",
				"lob_token: 'test_pub_bfe696d078118e777aecbd634939183'",
				"$lobToken .= \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lob_TOKEN := \"test_pub_bfe696d078118e777aecbd634939183\"",
				"lob_TOKEN ?= \"test_pub_bfe696d078118e777aecbd634939183\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(LobPubAPIToken())
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
