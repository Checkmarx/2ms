package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var FreemiusSecretKeyRegex = regexp.MustCompile(`(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`) //nolint:gocritic // Regex can be simplified but copied from gitleaks

func Freemius() *Rule {
	return &Rule{
		BaseRuleID:      "e2a0aff7-a9db-4fcd-87a0-59f843e8f9f5",
		Description:     "Detected a Freemius secret key, potentially exposing sensitive information.",
		RuleID:          "freemius-secret-key",
		Regex:           FreemiusSecretKeyRegex,
		Keywords:        []string{"secret_key"},
		Path:            regexp.MustCompile(`(?i)\.php$`),
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
