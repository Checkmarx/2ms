package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsanaClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "AsanaClientSecret validation",
			truePositives: []string{
				"asanaToken = opstbbke0ir9ull3f7qgt0ehl7vdeg22",
				"asana_token: 'opstbbke0ir9ull3f7qgt0ehl7vdeg22'",
				"asana_token: \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"var asanaToken string = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"String asanaToken = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\";",
				"var asanaToken = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"$asanaToken .= \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asanaToken = 'opstbbke0ir9ull3f7qgt0ehl7vdeg22'",
				"asanaToken=\"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asanaToken = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"{\"config.ini\": \"ASANA_TOKEN=opstbbke0ir9ull3f7qgt0ehl7vdeg22\\nBACKUP_ENABLED=true\"}",
				"asanaToken = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"  \"asanaToken\" => \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asana_TOKEN ::= \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"<asanaToken>\n    opstbbke0ir9ull3f7qgt0ehl7vdeg22\n</asanaToken>",
				"asanaToken := \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asana_TOKEN = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asana_TOKEN := \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asana_TOKEN :::= \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
				"asanaToken=opstbbke0ir9ull3f7qgt0ehl7vdeg22",
				"{\n    \"asana_token\": \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"\n}",
				"asana_token: opstbbke0ir9ull3f7qgt0ehl7vdeg22",
				"string asanaToken = \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\";",
				"asanaToken := `opstbbke0ir9ull3f7qgt0ehl7vdeg22`",
				"System.setProperty(\"ASANA_TOKEN\", \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\")",
				"asana_TOKEN ?= \"opstbbke0ir9ull3f7qgt0ehl7vdeg22\"",
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
			rule := ConvertNewRuleToGitleaksRule(AsanaClientSecret())
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
