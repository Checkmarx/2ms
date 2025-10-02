package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var MailgunPubKeyRegex = utils.GenerateSemiGenericRegex([]string{"mailgun"}, `pubkey-[a-f0-9]{32}`, true)

func MailGunPubAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "83133dbd-e5b6-4b5c-a37d-78e1c45abeac",
		Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
		RuleID:      "mailgun-pub-key",
		Regex:       MailgunPubKeyRegex,
		Keywords: []string{
			"mailgun",
		},
		Severity:        "High",
		Tags:            []string{TagPublicKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
