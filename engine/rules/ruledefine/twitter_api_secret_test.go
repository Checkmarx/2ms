package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwitterAPISecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TwitterAPISecret validation",
			truePositives: []string{
				"twitterToken = qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o",
				"twitter_token: qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o",
				"twitter_token: \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"string twitterToken = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\";",
				"twitterToken := \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitterToken := `qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o`",
				"var twitterToken = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitter_TOKEN ?= \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitterToken = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"{\"config.ini\": \"TWITTER_TOKEN=qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\\nBACKUP_ENABLED=true\"}",
				"<twitterToken>\n    qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\n</twitterToken>",
				"twitter_token: 'qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o'",
				"twitterToken = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitter_TOKEN = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitter_TOKEN := \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitterToken=qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o",
				"var twitterToken string = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"String twitterToken = \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\";",
				"twitterToken = 'qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o'",
				"System.setProperty(\"TWITTER_TOKEN\", \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\")",
				"twitterToken=\"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"{\n    \"twitter_token\": \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"\n}",
				"$twitterToken .= \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"  \"twitterToken\" => \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitter_TOKEN ::= \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
				"twitter_TOKEN :::= \"qc1p3chwtm2tciq53b8umwvs2p8fp2czy3jehs9j352yjyvn2o\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(TwitterAPISecret())
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
