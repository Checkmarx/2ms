package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// regex for rule
var OnePasswordServiceAccountTokenRegex = regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`)

func OnePasswordServiceAccountToken() *NewRule {
	// define rule
	return &NewRule{
		BaseRuleID:      "0ea85582-ea27-4f6f-b5f0-db3c4a75a07e",
		RuleID:          "1password-service-account-token",
		Description:     "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.",
		Regex:           OnePasswordServiceAccountTokenRegex,
		Entropy:         4,
		Keywords:        []string{"ops_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
