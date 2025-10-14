package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRapidAPIAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "RapidAPIAccessToken validation",
			truePositives: []string{
				"rapidapiToken=\"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"var rapidapiToken string = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken := `3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq`",
				"System.setProperty(\"RAPIDAPI_TOKEN\", \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\")",
				"rapidapi_TOKEN ::= \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapi_TOKEN :::= \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapi_TOKEN ?= \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken=3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq",
				"rapidapiToken = 3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq",
				"<rapidapiToken>\n    3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\n</rapidapiToken>",
				"rapidapi_token: '3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq'",
				"String rapidapiToken = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\";",
				"var rapidapiToken = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"  \"rapidapiToken\" => \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken := \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"$rapidapiToken .= \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"rapidapiToken = '3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq'",
				"rapidapi_TOKEN = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"{\n    \"rapidapi_token\": \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"\n}",
				"{\"config.ini\": \"RAPIDAPI_TOKEN=3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\\nBACKUP_ENABLED=true\"}",
				"rapidapi_token: 3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq",
				"rapidapi_token: \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
				"string rapidapiToken = \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\";",
				"rapidapi_TOKEN := \"3k7b18-qp98kcg_pyh_dcxcmqktnpu1lnpjiaut0s6iebn97yq\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(RapidAPIAccessToken())
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
