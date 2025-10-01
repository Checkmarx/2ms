package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DropboxShortLivedAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`, true)

func DropboxShortLivedAPIToken() *NewRule {
	return &NewRule{
		Description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
		RuleID:      "dropbox-short-lived-api-token",
		Regex:       DropboxShortLivedAPITokenRegex,
		Keywords:    []string{"dropbox"},
	}
}
