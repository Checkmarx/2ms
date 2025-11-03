package ruledefine

import (
	"regexp"
)

var frameioAPITokenRegex = regexp.MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`).String()

func FrameIO() *Rule {
	return &Rule{
		RuleID:          "96b38d4d-883b-4060-8b7e-6484f2c1cec4",
		Description:     "Found a Frame.io API token, potentially compromising video collaboration and project management.",
		RuleName:        "Frameio-Api-Token",
		Regex:           frameioAPITokenRegex,
		Keywords:        []string{"fio-u-"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
