package ruledefine

import (
	"regexp"
)

var openshiftUserTokenRegex = regexp.MustCompile(`\b(sha256~[\w-]{43})(?:[^\w-]|\z)`).String()

func OpenshiftUserToken() *Rule {
	return &Rule{
		RuleID:      "70583a50-6618-4935-b1d7-026abf806c45",
		Description: "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
		RuleName:    "Openshift-User-Token",
		Regex:       openshiftUserTokenRegex,
		Entropy:     3.5,
		Keywords: []string{
			"sha256~",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
