package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClojars(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Clojars validation",
			truePositives: []string{
				"clojarsToken=\"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojars_token: 'CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc'",
				"clojars_token: \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"string clojarsToken = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\";",
				"clojarsToken := \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"var clojarsToken = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"$clojarsToken .= \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"  \"clojarsToken\" => \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojarsToken = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojars_token: CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc",
				"clojarsToken := `CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc`",
				"clojarsToken = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojars_TOKEN = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojars_TOKEN ::= \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojars_TOKEN ?= \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojarsToken = CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc",
				"{\n    \"clojars_token\": \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"\n}",
				"<clojarsToken>\n    CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\n</clojarsToken>",
				"var clojarsToken string = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"String clojarsToken = \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\";",
				"clojarsToken = 'CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc'",
				"clojars_TOKEN :::= \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",
				"clojarsToken=CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc",
				"{\"config.ini\": \"CLOJARS_TOKEN=CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\\nBACKUP_ENABLED=true\"}",
				"System.setProperty(\"CLOJARS_TOKEN\", \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\")",
				"clojars_TOKEN := \"CLOJARS_4bfq11oxch4ob8rnle9kjmsgejd1pwha6ckhcmct0rkqldsfpqokkvvwoefc\"",

				"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(Clojars())
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
