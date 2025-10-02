package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBeamerApiToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Beamer validation",
			truePositives: []string{
				"  \"beamerToken\" => \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken = b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h",
				"{\n    \"beamer_token\": \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"\n}",
				"beamer_token: b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h",
				"beamer_token: 'b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h'",
				"string beamerToken = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\";",
				"$beamerToken .= \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamer_TOKEN := \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamer_TOKEN :::= \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken=b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h",
				"beamerToken := \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"String beamerToken = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\";",
				"var beamerToken = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamer_TOKEN ?= \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken=\"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"{\"config.ini\": \"BEAMER_TOKEN=b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\\nBACKUP_ENABLED=true\"}",
				"var beamerToken string = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken := `b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h`",
				"beamerToken = 'b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h'",
				"System.setProperty(\"BEAMER_TOKEN\", \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\")",
				"beamer_TOKEN = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamer_TOKEN ::= \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"<beamerToken>\n    b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\n</beamerToken>",

				"beamer_token: \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
				"beamerToken = \"b_lw=_afiwoy7m-2=urprdkhplfussqvgi5fjv_cmy2s-h\"",
			},
			falsePositives: []string{
				`│   ├── R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu`,
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
			rule := ConvertNewRuleToGitleaksRule(Beamer())
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
