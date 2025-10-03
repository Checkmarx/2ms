package rules

import (
	"regexp"
)

var OpenshiftUserTokenRegex = regexp.MustCompile(`\b(sha256~[\w-]{43})(?:[^\w-]|\z)`)

func OpenshiftUserToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "70583a50-6618-4935-b1d7-026abf806c45",
		Description: "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
		RuleID:      "openshift-user-token",
		Regex:       OpenshiftUserTokenRegex,
		Entropy:     3.5,
		Keywords: []string{
			"sha256~",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
