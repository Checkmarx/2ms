package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var DopplerAPITokenRegex = regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`)

func DopplerApiToken() *NewRule {
	return &NewRule{
		Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		RuleID:      "doppler-api-token",
		Regex:       DopplerAPITokenRegex,
		Entropy:     2,
		Keywords:    []string{`dp.pt.`},
	}
}
