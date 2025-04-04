package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func GenericCredential() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "generic-api-key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex: generateSemiGenericRegexWithAdditionalRegex([]string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		}, `[0-9a-z\-_.=]{10,150}`, true,
			[]string{
				`<key>\s*(?:access|auth|(?-i:[Aa]pi|API)|API_KEY|credential|creds|key|passw(?:or)?d|secret|token)\s*<\/key>\s*<string>\s*([\w.=-]{10,150}|[a-z0-9][a-z0-9+\/]{11,}={0,3})\s*<\/string>`,
			}),
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy: 3.5,
		Allowlist: config.Allowlist{
			StopWords: DefaultStopWords,
		},
	}

	// validate
	tps := []string{}
	fps := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

R5: Regulatory--21`,
	}
	return validate(r, tps, fps)
}
