package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DropboxShortLivedAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`, true)

func DropBoxShortLivedAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "e355f363-48a4-4125-b51a-4d267b81b0f8",
		Description:     "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
		RuleID:          "dropbox-short-lived-api-token",
		Regex:           DropboxShortLivedAPITokenRegex,
		Keywords:        []string{"dropbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
	}
}
