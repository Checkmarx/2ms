package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGocardlessAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GocardlessAPIToken validation",
			truePositives: []string{
				"{\n    \"gocardless_token\": \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"\n}",
				"{\"config.ini\": \"GOCARDLESS_TOKEN=live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\\nBACKUP_ENABLED=true\"}",
				"gocardless_token: 'live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of'",
				"string gocardlessToken = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\";",
				"String gocardlessToken = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\";",
				"var gocardlessToken = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"$gocardlessToken .= \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken := `live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of`",
				"gocardlessToken = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"System.setProperty(\"GOCARDLESS_TOKEN\", \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\")",
				"  \"gocardlessToken\" => \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardless_TOKEN = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardless_TOKEN ::= \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardless_TOKEN :::= \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken = 'live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of'",
				"gocardless_TOKEN := \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardless_TOKEN ?= \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken=\"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken = live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of",
				"<gocardlessToken>\n    live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\n</gocardlessToken>",
				"gocardless_token: live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of",
				"gocardless_token: \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"var gocardlessToken string = \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken := \"live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of\"",
				"gocardlessToken=live_49aspisymy=s-z850bhg709nytzlss=9c4rh0_of",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GoCardless())
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
