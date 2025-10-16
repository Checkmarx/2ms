package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrafanaAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GrafanaApiKey validation",
			truePositives: []string{
				"<grafana-api-keyToken>\n    eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\n</grafana-api-keyToken>",
				"String grafana-api-keyToken = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\";",
				"var grafana-api-keyToken = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"  \"grafana-api-keyToken\" => \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken=\"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"{\"config.ini\": \"GRAFANA-API-KEY_TOKEN=eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\\nBACKUP_ENABLED=true\"}",
				"string grafana-api-keyToken = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\";",
				"grafana-api-keyToken := \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken := `eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie`",
				"$grafana-api-keyToken .= \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken = 'eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie'",
				"grafana-api-keyToken=eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie",
				"{\n    \"grafana-api-key_token\": \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"\n}",
				"grafana-api-key_token: \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-key_TOKEN = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-key_TOKEN := \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-key_TOKEN ::= \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-key_TOKEN :::= \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-key_TOKEN ?= \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken = eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie",
				"grafana-api-key_token: eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie",
				"grafana-api-key_token: 'eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie'",
				"var grafana-api-keyToken string = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"grafana-api-keyToken = \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\"",
				"System.setProperty(\"GRAFANA-API-KEY_TOKEN\", \"eyJrIjoihkyjqznlttibexhgn6f84s4cp3jysnc0xbp80ebtiychklip781csc8smfx7rtpjn74bie\")",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GrafanaApiKey())
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
