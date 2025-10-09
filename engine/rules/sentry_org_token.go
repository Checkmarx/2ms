package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var SentryOrgTokenRegex = regexp.MustCompile(
	`\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)`) ////nolint:lll

func SentryOrgToken() *Rule {
	// format: sntrys_[base64_json]_[base64_secret]
	// the json contains the following fields : {"iat": ,"url": ,"region_url": ,"org": }
	// Specification: https://github.com/getsentry/rfcs/blob/main/text/0091-ci-upload-tokens.md
	// Some test cases from official parser:
	// https://github.com/getsentry/sentry-cli/blob/693d62167041846e2da823b7f3b0f21b673b5b1f/src/utils/auth_token/test.rs
	// To detect the token, this rule checks for the following base64-encoded json fragments :
	// eyJpYXQiO = `{"iat":`,
	// LCJyZWdpb25fdXJs = `,"region_url`
	// InJlZ2lvbl91cmwi = `"region_url"`
	// cmVnaW9uX3VybCI6 = `region_url":`
	return &Rule{
		BaseRuleID: "12818a31-52a8-44c7-b03b-19974d8fad04",
		RuleID:     "sentry-org-token",
		Description: "Found a Sentry.io Organization Token," +
			" risking unauthorized access to error tracking services and sensitive application data.",
		Regex:           SentryOrgTokenRegex,
		Entropy:         4.5,
		Keywords:        []string{"sntrys_eyJpYXQiO"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
