package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypeform(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Typeform validation",
			truePositives: []string{
				"{\n    \"typeformAPIToken_token\": \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"\n}",
				"typeformAPITokenToken := `tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp`",
				"typeformAPIToken_TOKEN ::= \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPIToken_TOKEN ?= \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPITokenToken=\"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPITokenToken = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPITokenToken=tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp",
				"typeformAPITokenToken = tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp",
				"<typeformAPITokenToken>\n    tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\n</typeformAPITokenToken>",
				"typeformAPIToken_token: tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp",
				"typeformAPIToken_token: 'tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp'",
				"typeformAPIToken_token: \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"string typeformAPITokenToken = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\";",
				"var typeformAPITokenToken string = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPITokenToken := \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"var typeformAPITokenToken = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"$typeformAPITokenToken .= \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"System.setProperty(\"TYPEFORMAPITOKEN_TOKEN\", \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\")",
				"typeformAPIToken_TOKEN = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPIToken_TOKEN := \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"{\"config.ini\": \"TYPEFORMAPITOKEN_TOKEN=tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\\nBACKUP_ENABLED=true\"}",
				"String typeformAPITokenToken = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\";",
				"typeformAPITokenToken = 'tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp'",
				"typeformAPITokenToken = \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"  \"typeformAPITokenToken\" => \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
				"typeformAPIToken_TOKEN :::= \"tfp_=p3bo8rjibic2q0pleb1e37nb57il9et5nb6qfnk1g51k5artvunyebuvnp\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(Typeform())
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
