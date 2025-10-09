package rules

import (
	"regexp"
)

var SidekiqSensitiveUrlRegex = regexp.MustCompile(`(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`) //nolint:gocritic,lll

func SidekiqSensitiveUrl() *Rule {
	return &Rule{
		BaseRuleID:      "547a55d8-782f-427b-bceb-4e9e6a0d9b93",
		Description:     "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
		RuleID:          "sidekiq-sensitive-url",
		Regex:           SidekiqSensitiveUrlRegex,
		Keywords:        []string{"gems.contribsys.com", "enterprise.contribsys.com"},
		Severity:        "High",
		Tags:            []string{TagSensitiveUrl},
		ScoreParameters: ScoreParameters{Category: CategoryBackgroundProcessingService, RuleType: 4},
	}
}
