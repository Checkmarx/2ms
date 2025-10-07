package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitbucketClientId(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "BitBucketClientID validation",
			truePositives: []string{
				"bitbucketToken = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"{\n    \"bitbucket_token\": \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"\n}",
				"<bitbucketToken>\n    w0hgmshg6uhgpqlbotbe15c2anbizrne\n</bitbucketToken>",
				"bitbucket_token: \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"var bitbucketToken string = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucketToken := `w0hgmshg6uhgpqlbotbe15c2anbizrne`",
				"bitbucket_TOKEN ::= \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucketToken=\"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"{\"config.ini\": \"BITBUCKET_TOKEN=w0hgmshg6uhgpqlbotbe15c2anbizrne\\nBACKUP_ENABLED=true\"}",
				"bitbucket_token: 'w0hgmshg6uhgpqlbotbe15c2anbizrne'",
				"bitbucketToken := \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"$bitbucketToken .= \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucketToken = 'w0hgmshg6uhgpqlbotbe15c2anbizrne'",
				"System.setProperty(\"BITBUCKET_TOKEN\", \"w0hgmshg6uhgpqlbotbe15c2anbizrne\")",
				"bitbucket_TOKEN = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucketToken=w0hgmshg6uhgpqlbotbe15c2anbizrne",
				"bitbucketToken = w0hgmshg6uhgpqlbotbe15c2anbizrne",
				"bitbucket_token: w0hgmshg6uhgpqlbotbe15c2anbizrne",
				"string bitbucketToken = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\";",
				"var bitbucketToken = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"  \"bitbucketToken\" => \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"String bitbucketToken = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\";",
				"bitbucketToken = \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucket_TOKEN := \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucket_TOKEN :::= \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
				"bitbucket_TOKEN ?= \"w0hgmshg6uhgpqlbotbe15c2anbizrne\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(BitBucketClientID())
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
