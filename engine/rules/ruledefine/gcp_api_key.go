package ruledefine

import (
	"regexp"
)

var GcpAPIKeyRegex = generateUniqueTokenRegex(`AIza[\w-]{35}`, false)

func GCPAPIKey() *Rule {
	return &Rule{
		BaseRuleID:  "ddb93a62-fcbd-466b-9e4b-695f5ee0d509",
		Description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
		RuleID:      "gcp-api-key",
		Regex:       GcpAPIKeyRegex,
		Entropy:     4,
		Keywords:    []string{"AIza"},
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					// example keys from https://github.com/firebase/firebase-android-sdk
					regexp.MustCompile(`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`),
					regexp.MustCompile(`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`),
					regexp.MustCompile(`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`),
					regexp.MustCompile(`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`),
					regexp.MustCompile(`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`),
					regexp.MustCompile(`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`),
					regexp.MustCompile(`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`),
					regexp.MustCompile(`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`),
					regexp.MustCompile(`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`),
					regexp.MustCompile(`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`),
					regexp.MustCompile(`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`),
					regexp.MustCompile(`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`),
					regexp.MustCompile(`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`),
					regexp.MustCompile(`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`),
					regexp.MustCompile(`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`),
					regexp.MustCompile(`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`),
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
