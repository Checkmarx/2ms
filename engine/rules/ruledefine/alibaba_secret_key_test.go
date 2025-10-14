package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlibabaSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Alibaba secret key validation",
			truePositives: []string{
				"alibaba_TOKEN ::= \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibabaToken=\"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"<alibabaToken>\n    6rn1zp5u4bfdcw758mx6wgx7glgzqx\n</alibabaToken>",
				"string alibabaToken = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\";",
				"String alibabaToken = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\";",
				"var alibabaToken = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibaba_TOKEN :::= \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibaba_TOKEN ?= \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibabaToken = 6rn1zp5u4bfdcw758mx6wgx7glgzqx",
				"{\n    \"alibaba_token\": \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"\n}",
				"alibaba_token: '6rn1zp5u4bfdcw758mx6wgx7glgzqx'",
				"alibabaToken := \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"$alibabaToken .= \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"System.setProperty(\"ALIBABA_TOKEN\", \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\")",
				"alibabaToken = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"{\"config.ini\": \"ALIBABA_TOKEN=6rn1zp5u4bfdcw758mx6wgx7glgzqx\\nBACKUP_ENABLED=true\"}",
				"var alibabaToken string = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibabaToken := `6rn1zp5u4bfdcw758mx6wgx7glgzqx`",
				"alibabaToken = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibaba_TOKEN := \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibabaToken=6rn1zp5u4bfdcw758mx6wgx7glgzqx",
				"alibaba_token: 6rn1zp5u4bfdcw758mx6wgx7glgzqx",
				"alibaba_token: \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibabaToken = '6rn1zp5u4bfdcw758mx6wgx7glgzqx'",
				"  \"alibabaToken\" => \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
				"alibaba_TOKEN = \"6rn1zp5u4bfdcw758mx6wgx7glgzqx\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AlibabaSecretKey())
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
