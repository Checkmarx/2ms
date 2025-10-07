package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlutterwaveEncryptionKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FlutterwaveEncKey validation",
			truePositives: []string{
				"flutterwavePubKeyToken=FLWSECK_TEST-5654db181ee4",
				"var flutterwavePubKeyToken string = \"FLWSECK_TEST-5654db181ee4\"",
				"var flutterwavePubKeyToken = \"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKeyToken = \"FLWSECK_TEST-5654db181ee4\"",
				"  \"flutterwavePubKeyToken\" => \"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKey_TOKEN ?= \"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKeyToken=\"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKeyToken = \"FLWSECK_TEST-5654db181ee4\"",
				"{\n    \"flutterwavePubKey_token\": \"FLWSECK_TEST-5654db181ee4\"\n}",
				"flutterwavePubKey_token: FLWSECK_TEST-5654db181ee4",
				"flutterwavePubKey_token: 'FLWSECK_TEST-5654db181ee4'",
				"flutterwavePubKey_token: \"FLWSECK_TEST-5654db181ee4\"",
				"string flutterwavePubKeyToken = \"FLWSECK_TEST-5654db181ee4\";",
				"flutterwavePubKey_TOKEN = \"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKeyToken = FLWSECK_TEST-5654db181ee4",
				"<flutterwavePubKeyToken>\n    FLWSECK_TEST-5654db181ee4\n</flutterwavePubKeyToken>",
				"flutterwavePubKeyToken := \"FLWSECK_TEST-5654db181ee4\"",
				"String flutterwavePubKeyToken = \"FLWSECK_TEST-5654db181ee4\";",
				"$flutterwavePubKeyToken .= \"FLWSECK_TEST-5654db181ee4\"",
				"System.setProperty(\"FLUTTERWAVEPUBKEY_TOKEN\", \"FLWSECK_TEST-5654db181ee4\")",
				"flutterwavePubKey_TOKEN ::= \"FLWSECK_TEST-5654db181ee4\"",
				"{\"config.ini\": \"FLUTTERWAVEPUBKEY_TOKEN=FLWSECK_TEST-5654db181ee4\\nBACKUP_ENABLED=true\"}",
				"flutterwavePubKeyToken := `FLWSECK_TEST-5654db181ee4`",
				"flutterwavePubKeyToken = 'FLWSECK_TEST-5654db181ee4'",
				"flutterwavePubKey_TOKEN := \"FLWSECK_TEST-5654db181ee4\"",
				"flutterwavePubKey_TOKEN :::= \"FLWSECK_TEST-5654db181ee4\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(FlutterwaveEncKey())
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
