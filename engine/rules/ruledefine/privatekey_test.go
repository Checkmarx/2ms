package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrivateKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PrivateKey validation",
			truePositives: []string{
				`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
-----END PRIVATE KEY-----`,
				`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3
yxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=
-----END RSA PRIVATE KEY-----
`,
				`-----BEGIN PGP PRIVATE KEY BLOCK-----
lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
			},
			falsePositives: []string{
				`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
				`-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PrivateKey())
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
