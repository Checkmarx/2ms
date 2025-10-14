package rules

import (
	"regexp"
)

var FrameioAPITokenRegex = regexp.MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`)

func FrameIO() *Rule {
	return &Rule{
		BaseRuleID:      "96b38d4d-883b-4060-8b7e-6484f2c1cec4",
		Description:     "Found a Frame.io API token, potentially compromising video collaboration and project management.",
		RuleID:          "frameio-api-token",
		Regex:           FrameioAPITokenRegex,
		Keywords:        []string{"fio-u-"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
