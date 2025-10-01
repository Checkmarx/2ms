package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DropboxAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"dropbox"}, utils.AlphaNumeric("15"), true)

func DropBoxAPISecret() *NewRule {
	return &NewRule{
		Description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
		RuleID:      "dropbox-api-token",
		Regex:       DropboxAPITokenRegex,
		Keywords:    []string{"dropbox"},
	}
}
