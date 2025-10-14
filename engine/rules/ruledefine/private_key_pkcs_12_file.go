package ruledefine

import (
	"regexp"
)

func PrivateKeyPKCS12File() *Rule {
	// https://en.wikipedia.org/wiki/PKCS_12
	return &Rule{
		BaseRuleID:  "aa9d108b-2a14-4291-868f-6d27909b20a4",
		Description: "Found a PKCS #12 file, which commonly contain bundled private keys.",
		RuleID:      "pkcs12-file",

		Path:     regexp.MustCompile(`(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`), //nolint:gocritic
		Severity: "High",
	}
}
