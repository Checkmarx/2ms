package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlickrAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FlickrAccessToken validation",
			truePositives: []string{
				"<flickrToken>\n    4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\n</flickrToken>",
				"string flickrToken = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\";",
				"var flickrToken string = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken=\"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickr_token: 4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6",
				"flickr_token: '4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6'",
				"flickrToken := `4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6`",
				"String flickrToken = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\";",
				"$flickrToken .= \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickr_TOKEN = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickr_TOKEN ::= \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken = 4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6",
				"var flickrToken = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken = '4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6'",
				"flickr_TOKEN := \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickr_TOKEN ?= \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken=4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6",
				"flickr_token: \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken := \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickrToken = \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"System.setProperty(\"FLICKR_TOKEN\", \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\")",
				"  \"flickrToken\" => \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"flickr_TOKEN :::= \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"",
				"{\n    \"flickr_token\": \"4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\"\n}",
				"{\"config.ini\": \"FLICKR_TOKEN=4sa7lwj8q8qupf15a5mdl5pyjdsvx6n6\\nBACKUP_ENABLED=true\"}",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FlickrAccessToken())
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
