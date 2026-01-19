package ruledefine

import (
	"regexp"
)

var twilioRegex = regexp.MustCompile(`SK[0-9a-fA-F]{32}`).String()

func Twilio() *Rule {
	return &Rule{
		RuleID:        "125b8e88-785b-4a52-ac05-790552e1907c",
		Description:   "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
		RuleName:      "Twilio-Api-Key",
		Regex:         twilioRegex,
		Entropy:       3,
		Keywords:      []string{"SK"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
