package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AuthenticatedURL() *config.Rule {
	regex, _ := regexp.Compile(`:\/\/(.+:.+)?@`)
	rule := config.Rule{
		Description: "Identify username:password inside URLS",
		RuleID:      "authenticated-url",
		Regex:       regex,
		Keywords:    []string{},
		SecretGroup: 1,
	}

	tPositives := []string{
		"mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
		"--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
		"https://abc:123@google.com",
	}

	fPositives := []string{
		"https://google.com",
		"https://google.com?user=abc&password=123",
	}

	return validate(rule, tPositives, fPositives)
}
