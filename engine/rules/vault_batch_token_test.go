package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultBatchToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "VaultBatchToken validation",
			truePositives: []string{
				"var vaultToken string = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"$vaultToken .= \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vaultToken = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vault_TOKEN ?= \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"{\n    \"vault_token\": \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"\n}",
				"vault_token: hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3",
				"vault_token: \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"string vaultToken = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\";",
				"String vaultToken = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\";",
				"vaultToken = 'hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3'",
				"vault_TOKEN :::= \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vaultToken = hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3",
				"{\"config.ini\": \"VAULT_TOKEN=hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\\nBACKUP_ENABLED=true\"}",
				"vaultToken := `hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3`",
				"System.setProperty(\"VAULT_TOKEN\", \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\")",
				"vault_TOKEN := \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vault_TOKEN ::= \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vaultToken=hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3",
				"vault_token: 'hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3'",
				"vaultToken := \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"var vaultToken = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"  \"vaultToken\" => \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vault_TOKEN = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vaultToken=\"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"vaultToken = \"hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\"",
				"<vaultToken>\n    hvb.mbh2sns98h-w6wls6wy0oahfa-xyo6jw2q89kp05s2q8jh-58vwu5sux2kw8lluzg524qpjsjd6ecoj519t4q-dl-kuzt-q178zijxr4hos9htsknj2ng7dyw1-puie735hsai75k3\n</vaultToken>",
				"hvb.AAAAAQJgxDgqsGNorpoOR7hPZ5SU-ynBvCl764jyRP_fnX7WvkdkDzGjbLNGdPdtlY33Als2P36yDZueqzfdGw9RsaTeaYXSH7E4RYSWuRoQ9YRKIw8o7mDDY2ZcT3KOB7RwtW1w1FN2eDqcy_sbCjXPaM1iBVH-mqMSYRmRd2nb5D1SJPeBzIYRqSglLc31wUGN7xEzyrKUczqOKsIcybQA",
			},
			falsePositives: []string{},
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
			rule := ConvertNewRuleToGitleaksRule(VaultBatchToken())
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
