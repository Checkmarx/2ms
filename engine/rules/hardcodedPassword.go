package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HardcodedPassword() *config.Rule {
	// This regex is the output regex of 'generic-api-key' rule from gitleaks, with the next changes:
	// 1. gitleaks/gitleaks#1267
	// 2. gitleaks/gitleaks#1265
	// 3. Minimum length of 4 characters (was 10)
	regex, _ := regexp.Compile(`(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:\s|'\s|"|\\){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\\|\s|=|\x60){0,5}([0-9a-z\-_.=!@#\$%\^\&\*]{4,150})(?:['|\"|\\|\n|\r|\s|\x60|;|<]|$)`)
	rule := config.Rule{
		Description: "Hardcoded password",
		RuleID:      "hardcoded-password",
		Regex:       regex,
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy:     0,
		SecretGroup: 1,
		Allowlist: config.Allowlist{
			StopWords: rules.DefaultStopWords,
		},
	}

	tPositives := []string{
		`"client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`"password: 'edf8f16608465858a6c9e3cccb97d3c2'"`,
		`<element password="edf8f16608465858a6c9e3cccb97d3c2" />`,
		`"client_id" : "edf8f16608465858a6c9e3cccb97d3c2"`,
		"https://google.com?user=abc&password=1234",
		`{ "access-key": "6da89121079f83b2eb6acccf8219ea982c3d79bccc", }`,
		`"{ \"access-key\": \"6da89121079f83b2eb6acccf8219ea982c3d79bccc\", }"`,
		"<password>edf8f16608465858a6c9e3cccb97d3c2</password>",
		"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
		`"client_secret" : "4v7b9n2k5h",`, // entropy: 3.32
		`"password: 'comp123!'"`,
		"<password>MyComp9876</password>", // entropy: 3.32
		`<element password="Comp4567@@" />`,
		"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
	}

	fPositives := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

		R5: Regulatory--21`,
		"GITHUB_TOKEN: ${GITHUB_TOKEN}",
		"password = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", // Stop word
		"password = 'your_password_here'",               // Stop word

	}

	return validate(rule, tPositives, fPositives)
}
