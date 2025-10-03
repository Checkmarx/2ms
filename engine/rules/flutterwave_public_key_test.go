package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlutterwavePublicKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FlutterwavePublicKey validation",
			truePositives: []string{
				"flutterwavePubKey_TOKEN ::= \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKey_TOKEN :::= \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKey_TOKEN ?= \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKeyToken=\"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKeyToken=FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X",
				"{\"config.ini\": \"FLUTTERWAVEPUBKEY_TOKEN=FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\\nBACKUP_ENABLED=true\"}",
				"flutterwavePubKey_token: FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X",
				"flutterwavePubKey_token: 'FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X'",
				"String flutterwavePubKeyToken = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\";",
				"$flutterwavePubKeyToken .= \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKeyToken = 'FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X'",
				"flutterwavePubKeyToken = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"string flutterwavePubKeyToken = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\";",
				"flutterwavePubKeyToken := \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"var flutterwavePubKeyToken = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKeyToken = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"System.setProperty(\"FLUTTERWAVEPUBKEY_TOKEN\", \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\")",
				"flutterwavePubKey_TOKEN = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKey_TOKEN := \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"flutterwavePubKeyToken = FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X",
				"{\n    \"flutterwavePubKey_token\": \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"\n}",
				"flutterwavePubKey_token: \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"var flutterwavePubKeyToken string = \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"  \"flutterwavePubKeyToken\" => \"FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\"",
				"<flutterwavePubKeyToken>\n    FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X\n</flutterwavePubKeyToken>",
				"flutterwavePubKeyToken := `FLWPUBK_TEST-d1a352b0c941f870679e8295756b7ce5-X`",
			},
			falsePositives: []string{},
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
			rule := ConvertNewRuleToGitleaksRule(FlutterwavePublicKey())
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
