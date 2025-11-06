package ruledefine

import (
	"regexp"
)

var gitlabFeedTokenRegex = regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`).String()

func GitlabFeedToken() *Rule {
	return &Rule{
		RuleID:          "adf3e374-d8ab-40e1-ac2a-91c75cbc7f7b",
		RuleName:        "Gitlab-Feed-Token",
		Description:     "Identified a GitLab feed token, risking exposure of user data.",
		Regex:           gitlabFeedTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glft-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
