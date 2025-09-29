package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var ArtifactoryReferenceTokenRegex = regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`)

func ArtifactoryReferenceToken() *NewRule {
	return &NewRule{
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		RuleID:      "artifactory-reference-token",
		Regex:       ArtifactoryReferenceTokenRegex,
		Keywords:    []string{"cmVmd"},
	}
}
