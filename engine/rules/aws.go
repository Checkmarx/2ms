package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var AWSRegex = regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`)

func AWS() *NewRule {
	return &NewRule{
		BaseRuleID:  "3551707c-5e9a-4f7a-b433-8d824900f3c4",
		RuleID:      "aws-access-token",
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		Regex:       AWSRegex,
		Entropy:     3,
		Keywords: []string{
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
			"A3T",  // todo: might not be a valid AWS token
			"AKIA", // Access key
			"ASIA", // Temporary (AWS STS) access key
			"ABIA", // AWS STS service bearer token
			"ACCA", // Context-specific credential
		},
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`.+EXAMPLE$`),
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
