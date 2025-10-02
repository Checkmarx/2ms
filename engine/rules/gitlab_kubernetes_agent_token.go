package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabKubernetesAgentTokenRegex = regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`)

func GitlabKubernetesAgentToken() *NewRule {
	return &NewRule{
		RuleID:          "gitlab-kubernetes-agent-token",
		Description:     "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
		Regex:           GitlabKubernetesAgentTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glagent-"},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
