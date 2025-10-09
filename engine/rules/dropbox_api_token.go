package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var DropboxAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"dropbox"}, utils.AlphaNumeric("15"), true)

func DropBoxAPISecret() *Rule {
	return &Rule{
		BaseRuleID:      "e20f40d2-0e7a-4b93-8206-6a7131c329c6",
		Description:     "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
		RuleID:          "dropbox-api-token",
		Regex:           DropboxAPITokenRegex,
		Keywords:        []string{"dropbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
	}
}
