package ruledefine

import (
	"regexp"
)

var gcpAPIKeyRegex = generateUniqueTokenRegex(`AIza[\w-]{35}`, false).String()

func GCPAPIKey() *Rule {
	return &Rule{
		RuleID:      "ddb93a62-fcbd-466b-9e4b-695f5ee0d509",
		Description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
		RuleName:    "Gcp-Api-Key",
		Regex:       gcpAPIKeyRegex,
		Entropy:     4,
		Keywords:    []string{"AIza"},
		AllowLists: []*AllowList{
			{
				Regexes: []string{
					// example keys from https://github.com/firebase/firebase-android-sdk
					regexp.MustCompile(`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`).String(),
					regexp.MustCompile(`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`).String(),
					regexp.MustCompile(`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`).String(),
					regexp.MustCompile(`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`).String(),
					regexp.MustCompile(`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`).String(),
					regexp.MustCompile(`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`).String(),
					regexp.MustCompile(`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`).String(),
					regexp.MustCompile(`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`).String(),
					regexp.MustCompile(`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`).String(),
					regexp.MustCompile(`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`).String(),
					regexp.MustCompile(`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`).String(),
					regexp.MustCompile(`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`).String(),
					regexp.MustCompile(`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`).String(),
					regexp.MustCompile(`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`).String(),
					regexp.MustCompile(`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`).String(),
					regexp.MustCompile(`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`).String(),
				},
			},
		},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryCloudPlatform,
		ScoreRuleType: 4,
	}
}
