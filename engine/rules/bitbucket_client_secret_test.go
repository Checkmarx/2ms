package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitbucketClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "BitbucketClientSecret validation",
			truePositives: []string{
				"bitbucket_TOKEN ?= \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken = 2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr",
				"{\n    \"bitbucket_token\": \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"\n}",
				"<bitbucketToken>\n    2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\n</bitbucketToken>",
				"bitbucketToken := \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken := `2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr`",
				"String bitbucketToken = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\";",
				"  \"bitbucketToken\" => \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucket_token: 2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr",
				"string bitbucketToken = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\";",
				"bitbucket_TOKEN :::= \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken=\"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken=2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr",
				"bitbucket_token: '2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr'",
				"bitbucket_token: \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"var bitbucketToken string = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken = '2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr'",
				"System.setProperty(\"BITBUCKET_TOKEN\", \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\")",
				"bitbucket_TOKEN = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"{\"config.ini\": \"BITBUCKET_TOKEN=2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\\nBACKUP_ENABLED=true\"}",
				"var bitbucketToken = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"$bitbucketToken .= \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucketToken = \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucket_TOKEN := \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
				"bitbucket_TOKEN ::= \"2xx420t16sep68pkly88kbhigtukky7mrmyth0nmldbn377e2hhpxnzt35mt4obr\"",
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
			rule := ConvertNewRuleToGitleaksRule(BitbucketClientSecret())
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
