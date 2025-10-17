package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDropboxAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DropBoxAPISecret validation",
			truePositives: []string{
				"dropbox_token: \"62qk4lutovd5dc7\"",
				"dropboxToken := \"62qk4lutovd5dc7\"",
				"var dropboxToken = \"62qk4lutovd5dc7\"",
				"dropboxToken = \"62qk4lutovd5dc7\"",
				"dropboxToken = \"62qk4lutovd5dc7\"",
				"{\"config.ini\": \"DROPBOX_TOKEN=62qk4lutovd5dc7\\nBACKUP_ENABLED=true\"}",
				"dropboxToken := `62qk4lutovd5dc7`",
				"String dropboxToken = \"62qk4lutovd5dc7\";",
				"  \"dropboxToken\" => \"62qk4lutovd5dc7\"",
				"dropbox_TOKEN ::= \"62qk4lutovd5dc7\"",
				"dropbox_TOKEN :::= \"62qk4lutovd5dc7\"",
				"dropbox_TOKEN ?= \"62qk4lutovd5dc7\"",
				"{\n    \"dropbox_token\": \"62qk4lutovd5dc7\"\n}",
				"string dropboxToken = \"62qk4lutovd5dc7\";",
				"var dropboxToken string = \"62qk4lutovd5dc7\"",
				"$dropboxToken .= \"62qk4lutovd5dc7\"",
				"dropboxToken = '62qk4lutovd5dc7'",
				"System.setProperty(\"DROPBOX_TOKEN\", \"62qk4lutovd5dc7\")",
				"dropbox_TOKEN := \"62qk4lutovd5dc7\"",
				"dropboxToken=\"62qk4lutovd5dc7\"",
				"<dropboxToken>\n    62qk4lutovd5dc7\n</dropboxToken>",
				"dropbox_TOKEN = \"62qk4lutovd5dc7\"",
				"dropboxToken=62qk4lutovd5dc7",
				"dropboxToken = 62qk4lutovd5dc7",
				"dropbox_token: 62qk4lutovd5dc7",
				"dropbox_token: '62qk4lutovd5dc7'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(DropBoxAPISecret())
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
