package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFreshbooksAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FreshbooksAccessToken validation",
			truePositives: []string{
				"  \"freshbooksToken\" => \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooks_TOKEN = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooks_TOKEN ?= \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"System.setProperty(\"FRESHBOOKS_TOKEN\", \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\")",
				"freshbooks_TOKEN := \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken=g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q",
				"{\"config.ini\": \"FRESHBOOKS_TOKEN=g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\\nBACKUP_ENABLED=true\"}",
				"freshbooks_token: \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken := \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"String freshbooksToken = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\";",
				"freshbooksToken = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooks_TOKEN ::= \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooks_TOKEN :::= \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken=\"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken = g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q",
				"{\n    \"freshbooks_token\": \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"\n}",
				"<freshbooksToken>\n    g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\n</freshbooksToken>",
				"freshbooks_token: 'g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q'",
				"string freshbooksToken = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\";",
				"var freshbooksToken string = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooks_token: g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q",
				"freshbooksToken := `g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q`",
				"var freshbooksToken = \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"$freshbooksToken .= \"g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q\"",
				"freshbooksToken = 'g9ptrr8i98yvh6rr1kf7b7k8lj14lzok6k5j6ibcmpvvdl2g0j9n7hnvjwi7yj1q'",
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
			rule := ConvertNewRuleToGitleaksRule(FreshbooksAccessToken())
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
