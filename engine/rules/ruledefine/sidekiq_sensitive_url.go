package ruledefine

import (
	"regexp"
)

var sidekiqSensitiveUrlRegex = regexp.MustCompile(`(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`).String() //nolint:gocritic,lll

func SidekiqSensitiveUrl() *Rule {
	return &Rule{
		RuleID:        "547a55d8-782f-427b-bceb-4e9e6a0d9b93",
		Description:   "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
		RuleName:      "Sidekiq-Sensitive-Url",
		Regex:         sidekiqSensitiveUrlRegex,
		Keywords:      []string{"gems.contribsys.com", "enterprise.contribsys.com"},
		Severity:      "High",
		Tags:          []string{TagSensitiveUrl},
		Category:      CategoryBackgroundProcessingService,
		ScoreRuleType: 4,
	}
}
