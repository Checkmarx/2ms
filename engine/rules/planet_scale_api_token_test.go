package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlanetScaleAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PlanetScaleAPIToken validation",
			truePositives: []string{
				"$planetScaleToken .= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken = 'pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--'",
				"planetScale_token: pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--",
				"var planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_TOKEN = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_TOKEN ::= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_TOKEN :::= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_TOKEN ?= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken=pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--",
				"{\n    \"planetScale_token\": \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"\n}",
				"<planetScaleToken>\n    pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\n</planetScaleToken>",
				"planetScaleToken := `pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--`",
				"planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\")",
				"  \"planetScaleToken\" => \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken=\"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_token: \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"var planetScaleToken string = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken := \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScale_TOKEN := \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\"",
				"planetScaleToken = pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\\nBACKUP_ENABLED=true\"}",
				"planetScale_token: 'pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--'",
				"string planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\";",
				"String planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--\";",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\")",
				"planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScaleToken=pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6",
				"<planetScaleToken>\n    pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\n</planetScaleToken>",
				"string planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\";",
				"var planetScaleToken string = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScaleToken := `pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6`",
				"var planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_token: 'pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6'",
				"$planetScaleToken .= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_TOKEN ::= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_TOKEN :::= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScaleToken=\"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_token: \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"  \"planetScaleToken\" => \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_TOKEN = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_TOKEN := \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScale_TOKEN ?= \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"planetScaleToken = pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6",
				"{\n    \"planetScale_token\": \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"\n}",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\\nBACKUP_ENABLED=true\"}",
				"planetScale_token: pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6",
				"planetScaleToken := \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\"",
				"String planetScaleToken = \"pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6\";",
				"planetScaleToken = 'pscale_tkn_gs-4nywmvgqydui3vonfqfk02w42o5--sovf51mhcq6'",
				"planetScale_TOKEN = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScale_TOKEN := \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScale_TOKEN ::= \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScaleToken := \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScale_TOKEN :::= \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScaleToken=\"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScaleToken = pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk",
				"string planetScaleToken = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\";",
				"planetScaleToken := `pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk`",
				"String planetScaleToken = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\";",
				"$planetScaleToken .= \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"  \"planetScaleToken\" => \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScale_TOKEN ?= \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"{\n    \"planetScale_token\": \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"\n}",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\\nBACKUP_ENABLED=true\"}",
				"<planetScaleToken>\n    pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\n</planetScaleToken>",
				"planetScale_token: pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk",
				"planetScale_token: 'pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk'",
				"planetScale_token: \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"var planetScaleToken string = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"var planetScaleToken = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScaleToken = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"planetScaleToken=pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk",
				"planetScaleToken = 'pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk'",
				"planetScaleToken = \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_tkn_00t-qo8p81hgv7vaf4ys1bkmgmh7gc_od=n3oitqs09llm113-5n9rmcbfhbxsqk\")",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PlanetScaleAPIToken())
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
