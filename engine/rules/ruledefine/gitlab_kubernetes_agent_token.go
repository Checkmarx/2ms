package ruledefine

import (
	"regexp"
)

var gitlabKubernetesAgentTokenRegex = regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`).String()

func GitlabKubernetesAgentToken() *Rule {
	return &Rule{
		RuleID:          "00955180-6ce6-4603-a1d3-f34d71a75414",
		RuleName:        "gitlab-kubernetes-agent-token",
		Description:     "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
		Regex:           gitlabKubernetesAgentTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glagent-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
