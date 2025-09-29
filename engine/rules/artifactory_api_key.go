package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var ArtifactoryApiKeyRegex = regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`)

func ArtifactoryApiKey() *NewRule {
	return &NewRule{
		Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
		RuleID:      "artifactory-api-key",
		Regex:       ArtifactoryApiKeyRegex,
		Keywords:    []string{"AKCp"},
	}
}
