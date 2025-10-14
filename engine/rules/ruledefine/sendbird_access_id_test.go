package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendbirdAccessID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SendbirdAccessID validation",
			truePositives: []string{
				"sendbirdToken = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"{\n    \"sendbird_token\": \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"\n}",
				"sendbird_token: \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"string sendbirdToken = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\";",
				"sendbirdToken := \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"  \"sendbirdToken\" => \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_TOKEN = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_TOKEN ::= \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbirdToken=d26c259b-58dc-b958-7aaa-97d5c453fa11",
				"<sendbirdToken>\n    d26c259b-58dc-b958-7aaa-97d5c453fa11\n</sendbirdToken>",
				"String sendbirdToken = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\";",
				"$sendbirdToken .= \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_TOKEN := \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_TOKEN :::= \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_TOKEN ?= \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbirdToken = d26c259b-58dc-b958-7aaa-97d5c453fa11",
				"{\"config.ini\": \"SENDBIRD_TOKEN=d26c259b-58dc-b958-7aaa-97d5c453fa11\\nBACKUP_ENABLED=true\"}",
				"var sendbirdToken string = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbirdToken := `d26c259b-58dc-b958-7aaa-97d5c453fa11`",
				"sendbirdToken = 'd26c259b-58dc-b958-7aaa-97d5c453fa11'",
				"sendbirdToken = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"System.setProperty(\"SENDBIRD_TOKEN\", \"d26c259b-58dc-b958-7aaa-97d5c453fa11\")",
				"sendbirdToken=\"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
				"sendbird_token: d26c259b-58dc-b958-7aaa-97d5c453fa11",
				"sendbird_token: 'd26c259b-58dc-b958-7aaa-97d5c453fa11'",
				"var sendbirdToken = \"d26c259b-58dc-b958-7aaa-97d5c453fa11\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SendbirdAccessID())
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
