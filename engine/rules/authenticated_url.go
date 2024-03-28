package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AuthenticatedURL() *config.Rule {
	regex, _ := regexp.Compile(`:\/\/(\w+:\w\S+)@\S+\.\S+`)
	rule := config.Rule{
		Description: "Identify username:password inside URLS",
		RuleID:      "authenticated-url",
		Regex:       regex,
		Keywords:    []string{"://"},
		SecretGroup: 1,
		Allowlist: config.Allowlist{
			StopWords: []string{"password"},
		},
	}

	tPositives := []string{
		"mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
		"--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
		"https://abc:123@google.com",
	}

	fPositives := []string{
		"https://google.com",
		"https://google.com?user=abc&password=123",
		`<img src="https://img.shields.io/static/v1?label=Threads&message=Follow&color=101010&link=https://threads.net/@mathrunet" alt="Follow on Threads" />`,
		`my [Linkedin](https://www.linkedin.com/in/rodriguesjeffdev/) or email: rodriguesjeff.dev@gmail.com`,
		`[![Gmail Badge](https://img.shields.io/badge/-VaibhavHariramani-d54b3d?style=flat-circle&labelColor=d54b3d&logo=gmail&logoColor=white&link=mailto:vaibhav.hariramani01@gmail.com)](mailto:vaibhav.hariramani01@gmail.com)`,
		`https://situmops:$(github_token)@github.com/$(Build.Repository.Name).git`,
		`'$cmd "unilinks://@@malformed.invalid.url/path?"$cmdSuffix',`,
		`Uri.parse('http://login:password@192.168.0.1:8888'),`,
	}

	return validate(rule, tPositives, fPositives)
}
