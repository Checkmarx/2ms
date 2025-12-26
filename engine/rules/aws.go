package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AWS() *config.Rule {
	return &config.Rule{
		RuleID:      "aws-access-token",
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.", //nolint:lll
		Regex:       regexp.MustCompile(`a`),
	}
}
