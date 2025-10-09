package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabSessionCookieRegex = regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`)

func GitlabSessionCookie() *Rule {
	return &Rule{
		BaseRuleID:      "fa980a88-6add-4a36-93c1-bd35610def6d",
		RuleID:          "gitlab-session-cookie",
		Description:     "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		Regex:           GitlabSessionCookieRegex,
		Entropy:         3,
		Keywords:        []string{"_gitlab_session="},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
