package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

var authPat = `(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))`

var CurlHeaderAuthRegex = regexp.MustCompile(
	// language=regexp
	fmt.Sprintf(`\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"%s"|'%s')(?:\B|\s|\z)`, authPat, authPat))

func CurlHeaderAuth() *NewRule {
	return &NewRule{
		BaseRuleID:  "9dcbb621-11db-4eac-a1ee-a945edba3438",
		RuleID:      "curl-auth-header",
		Description: "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.",
		Regex: regexp.MustCompile(
			// language=regexp
			fmt.Sprintf(`\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"%s"|'%s')(?:\B|\s|\z)`, authPat, authPat)),
		Entropy:         2.75,
		Keywords:        []string{"curl"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
	}
}
