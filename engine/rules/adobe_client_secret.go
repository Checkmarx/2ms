package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

func AdobeClientSecret() *NewRule {
	// define rule
	return &NewRule{
		RuleID:      "adobe-client-secret",
		Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false),
		Entropy:     2,
		Keywords:    []string{"p8e-"},
	}
}
