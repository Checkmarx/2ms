package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var TwilioRegex = regexp.MustCompile(`SK[0-9a-fA-F]{32}`)

func Twilio() *Rule {
	return &Rule{
		BaseRuleID:      "125b8e88-785b-4a52-ac05-790552e1907c",
		Description:     "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
		RuleID:          "twilio-api-key",
		Regex:           TwilioRegex,
		Entropy:         3,
		Keywords:        []string{"SK"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
