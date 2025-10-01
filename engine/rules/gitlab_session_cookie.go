package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabSessionCookieRegex = regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`)

func GitlabSessionCookie() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-session-cookie",
		Description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		Regex:       GitlabSessionCookieRegex,
		Entropy:     3,
		Keywords:    []string{"_gitlab_session="},
	}
}
