package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabFeedTokenRegex = regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`)

func GitlabFeedToken() *Rule {
	return &Rule{
		BaseRuleID:      "adf3e374-d8ab-40e1-ac2a-91c75cbc7f7b",
		RuleID:          "gitlab-feed-token",
		Description:     "Identified a GitLab feed token, risking exposure of user data.",
		Regex:           GitlabFeedTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glft-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
