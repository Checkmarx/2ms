package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLobAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "LobAPIToken validation",
			truePositives: []string{
				"lobToken = 'test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e'",
				"lobToken = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"  \"lobToken\" => \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lob_TOKEN := \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lob_TOKEN ::= \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lobToken = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"{\n    \"lob_token\": \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"\n}",
				"lob_token: \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"String lobToken = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\";",
				"lobToken = test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e",
				"string lobToken = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\";",
				"var lobToken string = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lob_TOKEN = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lob_TOKEN :::= \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lob_TOKEN ?= \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lobToken=\"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"<lobToken>\n    test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\n</lobToken>",
				"lob_token: test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e",
				"lob_token: 'test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e'",
				"lobToken := \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"lobToken := `test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e`",
				"$lobToken .= \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
				"System.setProperty(\"LOB_TOKEN\", \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\")",
				"lobToken=test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e",
				"{\"config.ini\": \"LOB_TOKEN=test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\\nBACKUP_ENABLED=true\"}",
				"var lobToken = \"test_5f0e52cbf78b6b4dabe3a7b38f459c35f9e\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(LobAPIToken())
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
