package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGcpAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GCPAPIKey validation",
			truePositives: []string{
				// non-word character at end
				`AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-`, // gitleaks:allow
			},
			falsePositives: []string{
				`GWw4hjABFzZCGiRpmlDyDdo87Jn9BN9THUA47muVRNunLxsa82tMAdvmrhOqNkRKiYMEAFbTJAIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDq`, // text boundary start
				`AIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDqabcd123`,                                                                   // text boundary end
				`apiKey: "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,                                                                // not enough entropy
				`AIZASYCO2CXRMC9ELSKLHLHRMBSWDEVEDZTLO2O`,                                                                          // incorrect case
				// example keys from https://github.com/firebase/firebase-android-sdk
				`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`,
				`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`,
				`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`,
				`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`,
				`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`,
				`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`,
				`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`,
				`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`,
				`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`,
				`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`,
				`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`,
				`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`,
				`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`,
				`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`,
				`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`,
				`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GCPAPIKey())
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
