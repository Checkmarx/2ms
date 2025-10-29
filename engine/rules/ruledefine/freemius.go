package ruledefine

import (
	"regexp"
)

var freemiusSecretKeyRegex = regexp.MustCompile(
	`(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`).String() //nolint:gocritic // Regex can be simplified but copied from gitleaks

func Freemius() *Rule {
	return &Rule{
		RuleID:          "e2a0aff7-a9db-4fcd-87a0-59f843e8f9f5",
		Description:     "Detected a Freemius secret key, potentially exposing sensitive information.",
		RuleName:        "Freemius-Secret-Key",
		Regex:           freemiusSecretKeyRegex,
		Keywords:        []string{"secret_key"},
		Path:            regexp.MustCompile(`(?i)\.php$`).String(),
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
	}
}
