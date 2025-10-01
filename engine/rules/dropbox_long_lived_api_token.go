package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DropboxLongLivedAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"dropbox"}, `[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`, true)

func DropboxLongLivedAPIToken() *NewRule {
	return &NewRule{
		Description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
		RuleID:      "dropbox-long-lived-api-token",
		Regex:       DropboxLongLivedAPITokenRegex,
		Keywords:    []string{"dropbox"},
	}
}
