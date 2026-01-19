package ruledefine

import (
	"regexp"
)

var gitlabSessionCookieRegex = regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`).String()

func GitlabSessionCookie() *Rule {
	return &Rule{
		RuleID:        "fa980a88-6add-4a36-93c1-bd35610def6d",
		RuleName:      "Gitlab-Session-Cookie",
		Description:   "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		Regex:         gitlabSessionCookieRegex,
		Entropy:       3,
		Keywords:      []string{"_gitlab_session="},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySourceCodeManagement,
		ScoreRuleType: 4,
	}
}
