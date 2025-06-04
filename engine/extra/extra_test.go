package extra

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/stretchr/testify/assert"
)

func TestAddExtraToSecret(t *testing.T) {
	tests := []struct {
		name           string
		secretValue    string
		expectedOutput interface{}
	}{
		{
			name:        "Valid JWT",
			secretValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im1vY2tOYW1lIn0.dummysignature",
			expectedOutput: map[string]interface{}{
				"sub":  "1234567890",
				"name": "mockName",
			},
		},
		{
			name:           "Invalid JWT format - it should contain exactly three parts separated by '.'",
			secretValue:    "invalidJWT.token",
			expectedOutput: "Invalid JWT token",
		},
		{
			name:           "Base64 decoding failure",
			secretValue:    "header." + base64.RawURLEncoding.EncodeToString([]byte("invalid_payload")) + ".signature",
			expectedOutput: "Failed to unmarshal JWT payload: invalid_payload",
		},
		{
			name: "Malformed base64",
			secretValue: fmt.Sprintf("header.%s.signature",
				base64.RawURLEncoding.EncodeToString([]byte("{malformed_json"))),
			expectedOutput: "Failed to unmarshal JWT payload: {malformed_json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &secrets.Secret{
				ID:           "test-secret",
				RuleID:       "jwt",
				Value:        tt.secretValue,
				ExtraDetails: make(map[string]interface{}),
			}

			AddExtraToSecret(secret)

			assert.Equal(t, tt.expectedOutput, secret.ExtraDetails["secretDetails"])
		})
	}
}
